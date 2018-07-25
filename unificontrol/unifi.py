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

CACHE_CERT = "CACHE_CERT"
        
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

        print("Sending request {}: {}\nrest={}".format(
            method, url, rest_dict))

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
        json_args = ["mac"] )

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
        json_args = ['usergroup_id'],
        method="PUT")

    #### To be implemented
    
    edit_usergroup = None
    create_usergroup = None
    delete_usergroup = None

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

    #### Not yet implemented

    create_site = None
    delete_site = None
    set_site_name = None
    set_site_country = None
    set_site_locale = None
    set_site_snmp = None
    set_site_mgmt = None
    set_site_guest_access = None
    set_site_ntp = None
    set_site_conectivity = None

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
