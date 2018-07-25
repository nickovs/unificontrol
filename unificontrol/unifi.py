#!/usr/bin/env python3

# Copyright 2018 Nicko van Someren
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# SPDX-License-Identifier: Apache-2.0

# Standard libraries
from inspect import signature, Signature, Parameter
from functools import wraps
import ssl
import tempfile
import atexit

# Dependencies
import requests

POSITIONAL_ONLY = Parameter.POSITIONAL_ONLY
POSITIONAL_OR_KEYWORD = Parameter.POSITIONAL_OR_KEYWORD
KEYWORD_ONLY = Parameter.KEYWORD_ONLY

# An heirarchy of exceptions for our error conditions.
class UnifiError(Exception):
    pass

class UnifiAPIError(UnifiError):
    pass

class UnifiTransportError(UnifiError):
    pass

class UnifiLoginError(UnifiError):
    pass

# This metaclass renames any method of a class that currently have a
# __name__ attribute of META_RENAME to instead have a function
# introspection name to match the attribute name

META_RENAME = "__TO_BE_RENAMED_LATER__"

class MetaNameFixer(type):
    def __init__(cls, name, bases, dct):
        for attr_name in dct:
            attr = dct[attr_name]
            if getattr(attr, "__name__", None) == META_RENAME:
                attr.__name__ = attr_name
        super(MetaNameFixer, cls).__init__(name, bases, dct)

# These are classes who's instances represent API calls to the Unifi controller

class _UnifiAPICall:
    def __init__(self, doc, endpoint,
                 path_arg_name=None, path_arg_optional=True,
                 json_args=None, json_body_name=None, json_fix=[],
                 rest_command=None, method=None,
                 need_login=True):
        self._endpoint = endpoint
        self._path_arg_name = path_arg_name
        self._json_args = json_args
        self._json_body_name = json_body_name
        self._rest = rest_command
        self._need_login = need_login
        if not isinstance(json_fix, (list, tuple)):
            json_fix = [json_fix]
        self._fixes = json_fix
        self.__doc__ = doc

        args = [Parameter('self', POSITIONAL_ONLY)]
        if path_arg_name:
            args.append(Parameter(path_arg_name, POSITIONAL_ONLY,
                                  default = None if path_arg_optional else Parameter.empty))
        if json_args:
            for arg_name in json_args:
                if isinstance(arg_name, tuple):
                    arg_name, default = arg_name
                else:
                    default = Parameter.empty
                args.append(Parameter(arg_name, KEYWORD_ONLY, default=default))
        if json_body_name:
            args.append(Parameter(json_body_name,
                                  KEYWORD_ONLY if path_arg_optional else POSITIONAL_OR_KEYWORD,
                                  default=None))

        self._sig = Signature(args)
        if method == None:
            if json_args or json_body_name or rest_command:
                method = "POST"
            else:
                method = "GET"

        self._method = method

    def _build_url(self, client, path_arg):
        return "https://{host}:{port}/api/s/{site}/{endpoint}{path}".format(
            host=client.host, port=client.port, site=client.site,
            endpoint=self._endpoint,
            path = "/" + path_arg if path_arg else "")

    def __call__(self, *args, **kwargs):
        bound = self._sig.bind(*args, **kwargs)
        bound.apply_defaults()
        # The first parameter is the 'self' of the API class to which it is attached
        client = bound.arguments["self"]
        path_arg = bound.arguments[self._path_arg_name] if self._path_arg_name else None
        rest_dict = bound.arguments[self._json_body_name] if self._json_body_name else {}
        if self._rest:
            rest_dict["cmd"] = self._rest
        if self._json_args:
            for arg_name in self._json_args:
                if isinstance(arg_name, tuple):
                    arg_name, _ = arg_name
                if arg_name not in bound.arguments:
                    raise TypeError("Argument {} is required".format(arg_name))
                if bound.arguments[arg_name]:
                    rest_dict[arg_name] = bound.arguments[arg_name]
        for fix in self._fixes:
            rest_dict = fix(rest_dict)
        url = self._build_url(client, path_arg)
        return client._execute(url, self._method, rest_dict, need_login=self._need_login)

class _UnifiAPICallNoSite(_UnifiAPICall):
    def _build_url(self, client, path_arg):
        return "https://{host}:{port}/api/{endpoint}{path}".format(
            host = client.host, port = client.port,
            endpoint = self._endpoint,
            path =  "/" + path_arg if path_arg else "")

# We want to have proper introspection and documentation for our
# methods but for some reason we you can't set a __signature__
# directly on a bound method. Instead we wrap it up and fix the
# signature on the wrapper.

def _make_wrapper(cls, *args, **kwargs):
    instance = cls(*args, **kwargs)
    def wrapper(client, *a, **kw):
        return instance(client, *a, **kw)
    wrapper.__name__ = META_RENAME
    wrapper.__doc__ = instance.__doc__
    wrapper.__signature__ = instance._sig
    return wrapper

def UnifiAPICall(*args, **kwargs):
    return _make_wrapper(_UnifiAPICall, *args, **kwargs)

def UnifiAPICallNoSite(*args, **kwargs):
    return _make_wrapper(_UnifiAPICallNoSite, *args, **kwargs)


# Functions here are fixers to fix up JSON objects before posting to
# the controller. This allows us to have cleaner function signatures
# when the underlying API is a bit verbose.

# Ensure messages with notes have the 'noted' flag set
def note_noted_fixer(d):
    if 'note' in d:
        if d['note']:
            d['noted'] = True
        else:
            del d['note']
    return d

# Arguments for user creation sit deeper in the JSON structure.
def user_object_nesting(d):
    return {"objects": [{"data":d}]}

# Convert a single mac into a list as necessary
def listify_macs(d):
    if 'macs' in d and isinstance(d['macs'], str):
        d['macs'] = [d['macs']]
    return d

# Functions to fix start and end times
def fix_start_now(d):
    if 'start' not in d or d['start'] == None:
        d['start'] = int(time.time())
    return d

def _fix_end_delta(d, delta):
    if 'end' not in d or d['end'] == None:
        d['end'] = d['start'] + delta
    return d

def fix_end_12hours(d):
    return _fix_end_delta(d, 12 * 3600)

def fix_end_7days(d):
    return _fix_end_delta(d, 7 * 24 * 3600)

def fix_end_1year(d):
    return _fix_end_delta(d, 365 * 24 * 3600)

# Ensure that requested attributes include the 'time' attribute
def fix_ensure_time_attrib(d):
    if 'attrs' not in d:
        d['attrs'] = []
    if 'time' not in d['attrs']:
        d['attrs'].append('time')
    return d

CACHE_CERT = "CACHE_CERT"

# Default lists of stats to return for various stat calls
_default_site_attributes = ['bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes', 'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time']

_default_ap_attributes = ['bytes', 'num_sta', 'time']

_default_user_attributes = ['time', 'rx_bytes', 'tx_bytes']

# The main Unifi client object

class UnifiClient(metaclass=MetaNameFixer):
    """An abstract interface to the Unifi controller"""

    def __init__(self, host="localhost", port=8443,
                 username="admin", password=None,
                 site=None, ssl_verify=False):
        self._host = host
        self._port = port
        self._user = username
        self._password = password
        self._site = site
        self._verify = ssl_verify
        self._session = requests.Session()
        self._exit_handler = None

        if ssl_verify == CACHE_CERT:
            self.cache_server_cert()

    def _exit(self):
        if self._verify:
            os.remove(self._verify)
            self._verify = False

    def __del__(self):
        if self._exit_handler:
            os.remove(self._verify)
            atexit.unregister(self._exit_handler)

    def cache_server_cert(self):
        cert = ssl.get_server_certificate((self._host, self._port))
        if cert:
            cert_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".pem", delete=False)
            cert_file.write(cert)
            cert_file.close()
            cert_name = cert_file.name
            self._verify = cert_name
            self._exit_handler = atexit.register(self._exit)
        else:
            raise Error("Failed to fetch SSL certificate")

    def _execute(self, url, method, rest_dict, need_login=True):
        request = requests.Request(method, url, json=rest_dict)
        ses = self._session

        r = ses.send(ses.prepare_request(request), verify=self._verify)

        # If we fail with unauthorised and need login then retry just once
        if r.status_code == 401 and need_login:
            try:
                self.login()
            except UnifiTransportError:
                if self._user and self._password:
                    raise UnifiLoginError("Invalid credentials")
                else:
                    raise UnifiLoginError("Need user name and password to log in")
            r = ses.send(ses.prepare_request(request), verify=self._verify)

        if r.ok:
            response = r.json()
            if 'meta' in response and response['meta']['rc'] != 'ok':
                raise UnifiAPIError(response['meta']['msg'])
            return response['data']
        else:
            raise UnifiTransportError("{}: {}".format(r.status_code, r.reason))

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def site(self):
        return self._site

    @site.setter
    def site(self, site_name):
        self._site = site_name

    # From here on down most of the methods are defined using an
    # abstract representation of the API.

    _login = UnifiAPICallNoSite(
        "raw login command",
        "login",
        json_args=["username", "password"],
        need_login=False)

    def login(self, username=None, password=None):
        "Log in to Unifi controller"
        self._login(username=username if username else self._user,
                    password=password if password else self._password)

    logout = UnifiAPICallNoSite(
        "Log out from Unifi controller",
        "logout",
        need_login=False)

    # Functions for dealing with guest and client devices

    authorize_guest = UnifiAPICall(
        "Authorize a client device",
        "cmd/stamgr",
        rest_command = "authorize-guest",
        json_args = ["mac",
                     "minutes",
                     ("up", None),
                     ("down", None),
                     ("MBytes", None),
                     ("ap_mac", None) ] )

    unauthorize_guest = UnifiAPICall(
        "Unauthorize a client device",
        "cmd/stamgr",
        rest_command = "unauthorize-guest",
        json_args = ["mac"] )

    reconnect_client = UnifiAPICall(
        "Force reconnection of a client device",
        "cmd/stamgr",
        rest_command = "kick-sta",
        json_args = ["mac"] )

    block_client = UnifiAPICall(
        "Block a client device",
        "cmd/stamgr",
        rest_command = "block-sta",
        json_args = ["mac"] )

    unblock_client = UnifiAPICall(
        "Unblock a client device",
        "cmd/stamgr",
        rest_command = "unblock-sta",
        json_args = ["mac"] )

    forget_client = UnifiAPICall(
        "Forget a client device",
        "cmd/stamgr",
        rest_command = "forget-sta",
        json_args = ["macs"],
        json_fix = [listify_macs] )

    create_client = UnifiAPICall(
        "Creat a new user/client device",
        "group/user",
        json_args = ["mac",
                     "usergroup_id",
                     ("name", None),
                     ("note", None)],
        json_fix = [note_noted_fixer, user_object_nesting] )

    set_client_note = UnifiAPICall(
        "Add, modify or remove a note on a client device",
        "upd/user",
        path_arg_name = "user_id",
        path_arg_optional = False,
        json_args = ["note"],
        json_fix = [note_noted_fixer],
        method="PUT" )

    set_client_name = UnifiAPICall(
        "Add, modify or remove a name on a client device",
        "upd/user",
        path_arg_name = "user_id",
        path_arg_optional = False,
        json_args = ["name"],
        method="PUT" )

    # Functions for retreiving statistics

    stat_5minutes_site = UnifiAPICall(
        "5 minutes site stats method",
        "stat/report/5minutes.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _default_site_attributes)],
        json_fix = [fix_start_now,
                    fix_end_12hours,
                    fix_ensure_time_attrib],
        )

    stat_hourly_site = UnifiAPICall(
        "Hourly site stats method",
        "stat/report/hourly.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _default_site_attributes)],
        json_fix = [fix_start_now,
                    fix_end_7days,
                    fix_ensure_time_attrib],
        )

    stat_daily_site = UnifiAPICall(
        "Daily site stats method",
        "stat/report/daily.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _default_site_attributes)],
        json_fix = [fix_start_now,
                    fix_end_1year,
                    fix_ensure_time_attrib],
    )

    stat_5minutes_aps = UnifiAPICall(
        "5 minutes stats method for a single access point or all access points",
        "stat/report/5minutes.ap",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _default_ap_attributes)],
        json_fix = [fix_start_now,
                    fix_end_12hours,
                    fix_ensure_time_attrib],
    )

    stat_hourly_aps = UnifiAPICall(
        "Hourly stats method for a single access point or all access points",
        "stat/report/hourly.ap",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _default_ap_attributes)],
        json_fix = [fix_start_now,
                    fix_end_7days,
                    fix_ensure_time_attrib],
    )

    stat_daily_aps = UnifiAPICall(
        "Daily stats method for a single access point or all access points",
        "stat/report/daily.ap",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _default_ap_attributes)],
        json_fix = [fix_start_now,
                    fix_end_1year,
                    fix_ensure_time_attrib],
     )

    stat_5minutes_user = UnifiAPICall(
        "5 minutes stats method for a single user/client device",
        "stat/report/5minutes.user",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _default_user_attributes)],
        json_fix = [fix_start_now,
                    fix_end_12hours,
                    fix_ensure_time_attrib],
    )

    stat_hourly_user = UnifiAPICall(
        "Hourly stats method for a a single user/client device",
        "stat/report/hourly.user",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _default_user_attributes)],
        json_fix = [fix_start_now,
                    fix_end_7days,
                    fix_ensure_time_attrib],
    )

    stat_daily_user = UnifiAPICall(
        "Daily stats method for a single user/client device",
        "stat/report/daily.user",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _default_user_attributes)],
        json_fix = [fix_start_now,
                    fix_end_1year,
                    fix_ensure_time_attrib],
    )

    stat_sessions = UnifiAPICall(
        "Show all login sessions",
        "stat/session",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('type', 'all')],
        json_fix = [fix_start_now,
                    fix_end_7days],
    )

    stat_sta_sessions_latest = UnifiAPICall(
        "Show latest 'n' login sessions for a single client device",
        "stat/session",
        json_args=['mac',
                   ('_limit', 5),
                   ('_sort', '-assoc_time')],
    )

    stat_auths = UnifiAPICall(
        "Show all authorizations",
        "stat/authorization",
        json_args=[('start', None),
                   ('end', None)],
        json_fix = [fix_start_now,
                    fix_end_7days],
    )

    list_allusers = UnifiAPICall(
        "List all client devices ever connected to the site",
        "stat/alluser",
        json_args = [('type', 'all'),
                     ('conn', 'all'),
                     ('within', 8760) ] )

    list_guests = UnifiAPICall(
        "List guest devices",
        "stat/guest",
        json_args = [('within', 8760) ] )

    list_clients = UnifiAPICall(
        "List currently connected client devices, or details on a single MAC address",
        "stat/sta",
        path_arg_name="client_mac")

    get_client_details = UnifiAPICall(
        "Get details about a client",
        "stat/user",
        path_arg_name="client_mac",
        path_arg_optional=False)

    list_usergroups = UnifiAPICall(
        "List user groups",
        "list/usergroup")

    set_usergroup =  UnifiAPICall(
        "Set the user group for a client",
        "upd/user",
        path_arg_name="client_mac",
        path_arg_optional=False,
        json_args = ['usergroup_id'],
        method="PUT")

    ### FIX ME: Does the JSON in this call need the group_id as _id as
    ### well having it in the path?

    edit_usergroup = UnifiAPICall(
        "Update user group",
        "rest/usergroup",
        path_arg_name="group_id",
        path_arg_optional=False,
        json_args=['site_id',
                   'name',
                   ('qos_rate_max_down', -1),
                   ('qos_rate_max_up', -1)],
        method="PUT",
    )

    create_usergroup = UnifiAPICall(
        "Create user group",
        "rest/usergroup",
        json_args=['name',
                   ('qos_rate_max_down', -1),
                   ('qos_rate_max_up', -1)],
    )

    delete_usergroup = UnifiAPICall(
        "Delete user group",
        "rest/usergroup",
        path_arg_name="group_id",
        path_arg_optional=False,
        method="DELETE",
    )

    list_health =  UnifiAPICall(
        "List health metrics",
        "stat/health")

    #### Should probably support '?scale=5minutes'
    list_dashboard =  UnifiAPICall(
        "List dashboard metrics",
        "stat/dashboard")

    list_users = UnifiAPICall(
        "List knows clients groups",
        "list/user")

    list_devices = UnifiAPICall(
        "List managed devices on this site",
        "stat/devices",
        path_arg_name="device_mac")

    list_tags = UnifiAPICall(
        "List known device tags",
        "rest/tag")

    list_rogueaps = UnifiAPICall(
        "List rogue or nearby APs",
        "stat/rogueap",
        json_args = [('within', 24)] )

    list_rogueknown = UnifiAPICall(
        "List rogue or nearby APs",
        "rest/rogueknown")

    list_sites = UnifiAPICallNoSite(
        "List sites on this controller",
        "self/sites")

    stat_sites = UnifiAPICallNoSite(
        "Get stats for sites on this controller",
        "stat/sites")

    create_site = UnifiAPICall(
        "Create a site",
        "cmd/sitemgr",
        rest_command="add-site",
        json_args=['desc'],
    )

    delete_site = UnifiAPICall(
        "Delete a site",
        "cmd/sitemgr",
        rest_command="delete-site",
        json_args=['site'],
    )

    set_site_name = UnifiAPICall(
        "Change a site's name",
        "cmd/sitemgr",
        rest_command="update-site",
        json_args=['desc'],
    )

    #### FIX ME: Need better doc string for setting
    set_site_country = UnifiAPICall(
        "Set site country",
        "rest/setting/country",
        path_arg_name="country_id",
        json_body_name="setting",
        method="PUT",
    )

    #### FIX ME: Need better doc string for setting
    set_site_locale = UnifiAPICall(
        "Set site locale",
        "rest/setting/locale",
        path_arg_name="locale_id",
        json_body_name="setting",
        method="PUT",
    )

    #### FIX ME: Need better doc string for setting
    set_site_snmp = UnifiAPICall(
        "Set site snmp",
        "rest/setting/snmp",
        path_arg_name="snmp_id",
        json_body_name="setting",
        method="PUT",
    )

    #### FIX ME: Need better doc string for setting
    set_site_mgmt = UnifiAPICall(
        "Set site mgmt",
        "rest/setting/mgmt",
        path_arg_name="gmt_id",
        json_body_name="setting",
        method="PUT",
    )

    set_site_guest_access = UnifiAPICall(
        "Set site guest access",
        "rest/setting/guest_access",
        path_arg_name="guest_access_id",
        json_body_name="setting",
        method="PUT",
    )

    set_site_ntp = UnifiAPICall(
        "Set site ntp",
        "rest/setting/ntp",
        path_arg_name="ntp_id",
        json_body_name="setting",
        method="PUT",
    )

    set_site_connectivity = UnifiAPICall(
        "Set site connectivity",
        "rest/setting/connectivity",
        path_arg_name="connectivity_id",
        json_body_name="setting",
        method="PUT",
    )

    list_admins = UnifiAPICall(
        "List admins",
        "cmd/sitemgr",
        rest_command="get-admins",
    )

    list_all_admins = UnifiAPICallNoSite(
        "List all admins",
        "stat/admin",
    )

    # invite_admin
    # Invite a new admin for access to the current site
    #
    # returns true on success
    # required parameter <name>           = string, name to assign to the new admin user
    # required parameter <email>          = email address to assign to the new admin user
    # optional parameter <enable_sso>     = boolean, whether or not SSO will be allowed for the new admin
    # default value is true which enables the SSO capability
    # optional parameter <readonly>       = boolean, whether or not the new admin will have readonly
    # permissions, default value is true which gives the new admin
    # administrator permissions
    # optional parameter <device_adopt>   = boolean, whether or not the new admin will have permissions to
    # adopt devices, default value is false. Only applies when readonly
    # is true.
    # optional parameter <device_restart> = boolean, whether or not the new admin will have permissions to
    # restart devices, default value is false. Only applies when readonly
    # is true.
    #
    # NOTES:
    # - after issuing a valid request, an invite will be sent to the email address provided
    # - issuing this command against an existing admin will trigger a "re-invite"
    #
    #
    #
    # invite_admin(($name, $email, $enable_sso = true, $readonly = false, $device_adopt = false, $device_restart = false))
    #
    #         if (!$this->is_loggedin) return false;
    #         $email_valid = filter_var(trim($email), FILTER_VALIDATE_EMAIL);
    #         if (!$email_valid) {
    #             trigger_error('The email address provided is invalid!');
    #             return false;
    #         }
    #
    #         $json = ['name' => trim($name), 'email' => trim($email), 'for_sso' => $enable_sso, 'cmd' => 'invite-admin'];
    #         if ($readonly) {
    #             $json['role'] = 'readonly';
    #             $permissions = [];
    #             if ($device_adopt) {
    #                 $permissions[] = "API_DEVICE_ADOPT";
    #             }
    #
    #             if ($device_restart) {
    #                 $permissions[] = "API_DEVICE_RESTART";
    #             }
    #
    #             if (count($permissions) > 0) {
    #                 $json['permissions'] = $permissions;
    #             }
    #         }
    #
    #         $json     = json_encode($json);
    #         $response = $this->exec_curl('/api/s/'.$this->site.'/cmd/sitemgr', 'json='.$json);
    #         return $this->process_response_boolean($response);
    #

    invite_admin = UnifiAPICall(
        "Invite a new admin for access to the current site",
        "cmd/sitemgr",
        json_args=[],
    )

    revoke_admin = UnifiAPICall(
        "Revoke an admin",
        "cmd/sitemgr",
        rest_command="revoke-admin",
        json_args=['admin'],
    )

    list_wlan_groups = UnifiAPICall(
        "List wlan_groups",
        "list/wlangroup",
    )

    stat_sysinfo = UnifiAPICall(
        "Show sysinfo",
        "stat/sysinfo",
    )

    stat_status = UnifiAPICallNoSite(
        "Get controller status",
        "status",
    )

    list_self = UnifiAPICall(
        "Get info about the logged in user",
        "self",
    )

    list_vouchers = UnifiAPICall(
        "List vouchers",
        "stat/voucher",
        json_args=['create_time'],
    )

    #### FIX ME: Should add support for 'within' parameter
    stat_payment = UnifiAPICall(
        "List payments",
        "stat/payment",
    )

    create_hotspotop = UnifiAPICall(
        "Create hotspot operator (using REST)",
        "rest/hotspotop",
        json_args=['name',
                   'x_password',
                   'nate'],
        json_fix = [note_noted_fixer],
    )

    list_hotspotop = UnifiAPICall(
        "List hotspot operators (using REST)",
        "rest/hotspotop",
    )

    create_voucher = UnifiAPICall(
        "Create voucher(s)",
        "cmd/hotspot",
        json_args=['minutes',
                   ('count', 1),
                   ('quota', 0),
                   ('note', None),
                   ('up', None),
                   ('down', None),
                   ('MBytes', None)],
    )

    #### FIX ME: This needs a way to rename ID arguments
    revoke_voucher = UnifiAPICall(
        "Revoke voucher",
        "cmd/hotspot",
        rest_command="delete-voucher",
        json_args=['_id'],
    )

    #### FIX ME: This needs a way to rename ID arguments
    extend_guest_validity = UnifiAPICall(
        "Extend guest validity",
        "cmd/hotspot",
        rest_command="extend",
        json_args=['_id'],
    )

    list_portforward_stats = UnifiAPICall(
        "List port forwarding stats",
        "stat/portforward",
    )

    list_dpi_stats = UnifiAPICall(
        "List deep packet inspection stats",
        "stat/dpi",
    )

    list_current_channels = UnifiAPICall(
        "List current channels",
        "stat/current-channel",
    )

    list_country_codes = UnifiAPICall(
        "List country codes",
        "stat/ccode",
    )

    list_portforwarding = UnifiAPICall(
        "List port forwarding settings",
        "list/portforward",
    )

    list_dynamicdns = UnifiAPICall(
        "List dynamic DNS settings",
        "list/dynamicdns",
    )

    list_portconf = UnifiAPICall(
        "List port configurations",
        "list/portconf",
    )

    list_extension = UnifiAPICall(
        "List VoIP extensions",
        "list/extension",
    )

    list_settings = UnifiAPICall(
        "List site settings",
        "get/setting",
    )

    adopt_device = UnifiAPICall(
        "Adopt a device to the selected site",
        "cmd/devmgr",
        rest_command="adopt",
        json_args=['mac'],
    )

    restart_ap = UnifiAPICall(
        "Reboot an access point",
        "cmd/devmgr",
        rest_command="restart",
        json_args=['mac'],
    )

    disable_ap = UnifiAPICall(
        "Disable/enable an access point (using REST)",
        "rest/device",
        path_arg_name="ap_id",
        path_arg_optional=False,
        json_args=['disabled'],
        method="PUT",
    )

    #### FIX ME: Need do document values ['off', 'on', 'default']
    led_override = UnifiAPICall(
        "Override LED mode for a device (using REST)",
        "rest/device",
        path_arg_name="device_id",
        path_arg_optional=False,
        json_args=['led_override'],
        method="PUT",
    )


    # locate_ap
    # Toggle flashing LED of an access point for locating purposes
    #
    # return true on success
    # required parameter <mac>    = device MAC address
    # required parameter <enable> = boolean; true will enable flashing LED, false will disable
    #
    # NOTES:
    # replaces the old set_locate_ap() and unset_locate_ap() methods/functions
    #
    #
    #
    # locate_ap(($mac, $enable))
    #
    #         if (!$this->is_loggedin) return false;
    #         $mac      = strtolower($mac);
    #         $cmd      = (($enable) ? 'set-locate' : 'unset-locate');
    #         $json     = json_encode(['cmd' => $cmd, 'mac' => $mac]);
    #         $response = $this->exec_curl('/api/s/'.$this->site.'/cmd/devmgr', 'json='.$json);
    #         return $this->process_response_boolean($response);
    #

    locate_ap = UnifiAPICall(
        "Toggle flashing LED of an access point for locating purposes",
        "cmd/devmgr",
        rest_command="$cmd",
        json_args=['mac'],
    )

    site_leds = UnifiAPICall(
        "Toggle LEDs of all the access points ON or OFF",
        "set/setting/mgmt",
        json_args=['led_enabled'],
    )

    set_ap_radiosettings = UnifiAPICall(
        "Update access point radio settings",
        "upd/device",
        path_arg_name="ap_id",
        path_arg_optional=False,
        json_args=['radio_table', 'channel', 'ht', 'tx_power_mode', 'tx_power'],
    )

    rename_ap = UnifiAPICall(
        "Rename access point",
        "upd/device",
        path_arg_name="ap_id",
        path_arg_optional=False,
        json_args=['name'],
    )

    move_device = UnifiAPICall(
        "Move a device to another site",
        "cmd/sitemgr",
        rest_command="move-device",
        json_args=['site', 'mac'],
    )

    delete_device = UnifiAPICall(
        "Delete a device from the current site",
        "cmd/sitemgr",
        rest_command="delete-device",
        json_args=['mac'],
    )

    list_networkconf = UnifiAPICall(
        "List network settings",
        "rest/networkconf",
    )

    #### FIX ME: Need better doc string for setting
    create_network = UnifiAPICall(
        "Create a network",
        "rest/networkconf",
        json_body_name='settings',
        method="POST",
    )

    #### FIX ME: Need better doc string for setting
    set_networksettings = UnifiAPICall(
        "Update network settings, base",
        "rest/networkconf",
        path_arg_name="network_id",
        path_arg_optional=False,
        json_body_name='settings',
        method="PUT",
    )

    delete_network = UnifiAPICall(
        "Delete a network (using REST)",
        "rest/networkconf",
        path_arg_name="network_id",
        path_arg_optional=False,
        method="DELETE",
    )


    list_wlanconf = UnifiAPICall(
        "List wireless LAN settings for all or one network",
        "rest/wlanconf",
        path_arg_name="wlan_id")

    _raw_set_wlan_settings = UnifiAPICall(
        "Low-level function to set wireless LAN settings",
        "rest/wlanconf",
        path_arg_name="wlan_id",
        path_arg_optional = False,
        json_body_name="settings",
        method="PUT")

    def set_wlan_settings(self, wlan_id, passphrase, ssid=None):
        settings={"x_passphrase": passphrase}
        if ssid is not None:
            settings['name'] = ssid

        return self._raw_set_wlan_settings(wlan_id, settings=settings)

    def enable_wlan(self, wlan_id, enabled):
        return self._raw_set_wlan_settings(wlan_id, {"enabled": bool(enabled)})

    def set_wlan_mac_filter(self, wlan_id, enabled, whitelist=False, mac_list=[]):
        "Set wireless LAN MAC filtering policy"
        settings = {"mac_filter_enabled": enabled,
                    "mac_filter_policy": 'allow' if whitelist else 'deny',
                    "mac_filter_list": mac_list}
        return self._raw_set_wlan_settings(wlan_id, settings=settings)

    delete_wlan = UnifiAPICall(
        "Delete a wlan (using REST)",
        "rest/wlanconf",
        path_arg_name="wlan_id",
        path_arg_optional=False,
        method="DELETE",
    )


    # list_events
    # List events
    #
    # returns an array of known events
    # optional parameter <historyhours> = hours to go back, default value is 720 hours
    # optional parameter <start>        = which event number to start with (useful for paging of results), default value is 0
    # optional parameter <limit>        = number of events to return, default value is 3000
    #
    #
    #
    # list_events(($historyhours = 720, $start = 0, $limit = 3000))
    #
    #         if (!$this->is_loggedin) return false;
    #         $json     = ['_sort' => '-time', 'within' => intval($historyhours), 'type' => null, '_start' => intval($start), '_limit' => intval($limit)];
    #         $json     = json_encode($json);
    #         $response = $this->exec_curl('/api/s/'.$this->site.'/stat/event', 'json='.$json);
    #         return $this->process_response($response);
    #

    #list_events = UnifiAPICall(
    #    "List events",
    #    "stat/event",
    #    json_args=[***$json***],
    #)

    list_alarms = UnifiAPICall(
        "List alarms",
        "list/alarm",
    )

    count_alarms = UnifiAPICall(
        "Count alarms",
        "cnt/alarm",
    )

    archive_alarm = UnifiAPICall(
        "Archive alarms(s)",
        "cmd/evtmgr",
        rest_command="archive-alarm",
        json_args=['_id'],
        method="POST",
    )

    archive_all_alarms = UnifiAPICall(
        "Archive alarms(s)",
        "cmd/evtmgr",
        rest_command="archive-all-alarms",
        method="POST",
    )

    upgrade_device = UnifiAPICall(
        "Upgrade a device to the latest firmware",
        "cmd/devmgr/upgrade",
        json_args=['mac'],
    )

    upgrade_device_external = UnifiAPICall(
        "Upgrade a device to a specific firmware file",
        "cmd/devmgr/upgrade-external",
        json_args=['mac', 'url'],
    )

    start_rolling_upgrade = UnifiAPICall(
        "Start rolling upgrade",
        "cmd/devmgr",
        rest_command='set-rollupgrade',
    )

    cancel_rolling_upgrade = UnifiAPICall(
        "Cancel rolling upgrade",
        "cmd/devmgr",
        rest_command='unset-rollupgrade',
    )

    power_cycle_switch_port = UnifiAPICall(
        "Power-cycle the PoE output of a switch port",
        "cmd/devmgr",
        rest_command = 'power-cycle',
        json_args=['mac', 'port_idx'],
    )

    spectrum_scan = UnifiAPICall(
        "Trigger an RF scan by an AP",
        "cmd/devmgr",
        rest_command = 'spectrum-scan',
        json_args=['mac'],
    )

    spectrum_scan_state = UnifiAPICall(
        "Check the RF scanning state of an AP",
        "stat/spectrum-scan",
        path_arg_name="ap_mac",
        path_arg_optional=False,
    )

    set_device_settings_base = UnifiAPICall(
        "Update device settings, base",
        "rest/device",
        path_arg_name="device_id",
        path_arg_optional=False,
        json_body_name='settings',
        method="PUT",
    )

    list_radius_profiles = UnifiAPICall(
        "List Radius profiles",
        "rest/radiusprofile",
    )

    list_radius_accounts = UnifiAPICall(
        "List Radius user accounts",
        "rest/account",
    )

    create_radius_account = UnifiAPICall(
        "Create a Radius user account (using REST)",
        "rest/account",
        json_args=['name',
                   'x_password',
                   'tunnel_type',
                   'tunnel_medium_type',
                   ('vlan', None)],
        method="POST",
    )

    set_radius_account_base = UnifiAPICall(
        "Update Radius account, base",
        "rest/account",
        path_arg_name="account_id",
        path_arg_optional=False,
        json_body_name='account_details',
        method="PUT",
    )

    delete_radius_account = UnifiAPICall(
        "Delete a Radius account (using REST)",
        "rest/account",
        path_arg_name="account_id",
        path_arg_optional=False,
        method="DELETE",
    )
