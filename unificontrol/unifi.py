#!/usr/bin/env python3

# pylint: disable=too-many-lines

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

"""Implementation of the Unifi controller API client"""


# Standard libraries
import ssl
import tempfile
import atexit
import os

# Dependencies
import requests

from .exceptions import UnifiAPIError, UnifiTransportError, UnifiLoginError
from .metaprogram import UnifiAPICall, UnifiAPICallNoSite, MetaNameFixer
from .json_fixers import (fix_note_noted, fix_user_object_nesting, fix_macs_list,
                          fix_end_now, fix_start_12hours, fix_start_7days, fix_start_1year,
                          fix_ensure_time_attrib, fix_constants, fix_arg_names,
                          fix_enforce_values, fix_locate_ap_cmd, fix_check_email,
                          fix_admin_permissions, fix_times_as_ms)
from .pinned_requests import PinningHTTPSAdapter

#: A tag to indicate that the client should fetch the server's SSL certificate
#: when it is created and then pin to that certificate.
FETCH_CERT = "FETCH_CERT"

# Default lists of stats to return for various stat calls
_DEFAULT_SITE_ATTRIBUTES = ['bytes', 'wan-tx_bytes', 'wan-rx_bytes',
                            'wlan_bytes', 'num_sta', 'lan-num_sta',
                            'wlan-num_sta', 'time']
_DEFAULT_AP_ATTRIBUTES = ['bytes', 'num_sta', 'time']
_DEFAULT_USER_ATTRIBUTES = ['time', 'rx_bytes', 'tx_bytes']

X_PASSWORD_FIX=fix_arg_names({"password":"x_passowrd"})


# The main Unifi client object

class UnifiClient(metaclass=MetaNameFixer):
    # pylint: disable=too-many-instance-attributes, too-many-arguments
    """An abstract interface to the Unifi controller

    Args:
        host (str): hostname of Unifi controller
        port (int): port on which controller is to be accessed
        username (str): user name for admin account
        password (str): password for admin account
        site (str): identifier of site to be managed
        cert (str or bytes): Server SSL certificate to pin for secure access.
            Pass ``None`` to use regular certificate verification or the
            constant ``FETCH_CERT`` to use the current certificate of the server
            and pin that cert for future accesses.
    """

    def __init__(self, host="localhost", port=8443,
                 username="admin", password=None, site="default",
                 cert=FETCH_CERT):
        self._host = host
        self._port = port
        self._user = username
        self._password = password
        self._site = site
        self._session = requests.session()
        self._exit_handler = None

        if cert == FETCH_CERT:
            cert = ssl.get_server_certificate((host, port))

        if cert is not None:
            adaptor = PinningHTTPSAdapter(cert)
            self._session.mount("https://{}:{}".format(host, port), adaptor)

    def _execute(self, url, method, rest_dict, need_login=True):
        request = requests.Request(method, url, json=rest_dict)
        ses = self._session

        resp = ses.send(ses.prepare_request(request))

        # If we fail with unauthorised and need login then retry just once
        if resp.status_code == 401 and need_login:
            try:
                self.login()
            except UnifiTransportError:
                if self._user and self._password:
                    raise UnifiLoginError("Invalid credentials")
                else:
                    raise UnifiLoginError("Need user name and password to log in")
            resp = ses.send(ses.prepare_request(request))

        if resp.ok:
            response = resp.json()
            if 'meta' in response and response['meta']['rc'] != 'ok':
                raise UnifiAPIError(response['meta']['msg'])
            return response['data']
        else:
            raise UnifiTransportError("{}: {}".format(resp.status_code, resp.reason))

    @property
    def host(self):
        """str: Host name of contoller"""
        return self._host

    @property
    def port(self):
        """str: Port for accessing controller"""
        return self._port

    @property
    def site(self):
        """str: Identifier of site being managed"""
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
        """Log in to Unifi controller

        Args:
            username (str): `optional` user name for admin account
            password (str): `optional` password for admin account

        The username and password arguments are optional if they were provided
        when the client was created.
        """
        self._login(username=username if username else self._user,
                    password=password if password else self._password)

    logout = UnifiAPICallNoSite(
        "Log out from Unifi controller",
        "logout",
        need_login=False)

    # Functions for dealing with guest and client devices

    authorize_guest = UnifiAPICall(
        """Authorize a client device

        Args:
            mac (str): MAC address of the guest client to be authorized
            minutes (int): duration for which the client is authorised
            up (int): `optional` upstream bandwidth limit in Kb/sec
            down (int): `optional` downstream bandwidth limit in Kb/sec
            MBytes (int): `optional` total data volume limit in megabytes
            ap_mac (str): `optional` MAC address of the access point to
                which the client will attach
        """,
        "cmd/stamgr",
        rest_command="authorize-guest",
        json_args=["mac",
                   "minutes",
                   ("up", None),
                   ("down", None),
                   ("MBytes", None),
                   ("ap_mac", None)],
        )

    unauthorize_guest = UnifiAPICall(
        """Unauthorize a guest client device

        Args:
            mac (str): MAC address of guest client to unauthorize
        """,
        "cmd/stamgr",
        rest_command="unauthorize-guest",
        json_args=["mac"],
        )

    reconnect_client = UnifiAPICall(
        """Force reconnection of a client device

        Args:
            mac (str): MAC address of guest client to reconnect
        """,
        "cmd/stamgr",
        rest_command="kick-sta",
        json_args=["mac"],
        )

    block_client = UnifiAPICall(
        """Block a client device

        Args:
            mac (str): MAC address of guest client to block
        """,
        "cmd/stamgr",
        rest_command="block-sta",
        json_args=["mac"],
        )

    unblock_client = UnifiAPICall(
        """Unblock a client device

        Args:
            mac (str): MAC address of guest client to unblock
        """,
        "cmd/stamgr",
        rest_command="unblock-sta",
        json_args=["mac"],
        )

    forget_client = UnifiAPICall(
        """Forget a client device

        Args:
            mac (str): One or a litst of MAC addresses of guest clients to forget

        Note:
            Requires version 5.9 of the controller or later.

        """,
        "cmd/stamgr",
        rest_command="forget-sta",
        json_args=["macs"],
        json_fix=[fix_macs_list],
        )

    create_client = UnifiAPICall(
        """Creat a new user/client device

        Args:
            mac (str): MAC address of new client
            usergroup_id (str): ``_id`` value for the user group for the client
            name (str): `optional` name for the new client
            note (str): `optional` note to attach to the new client
        """,
        "group/user",
        json_args=["mac",
                   "usergroup_id",
                   ("name", None),
                   ("note", None)],
        json_fix=[fix_note_noted, fix_user_object_nesting],
        )

    set_client_note = UnifiAPICall(
        """Add, modify or remove a note on a client device

        Args:
            user_id (str): ``_id`` value of the user for which the note is set
            note (str): Note to attach, or None to remove note
        """,
        "upd/user",
        path_arg_name="user_id",
        path_arg_optional=False,
        json_args=["note"],
        json_fix=[fix_note_noted],
        method="PUT",
        )

    set_client_name = UnifiAPICall(
        """Add, modify or remove a name of a client device

        Args:
            user_id (str): ``_id`` value of the user for which the name is set
            name (str): name to attach, or None to remove name
        """,
        "upd/user",
        path_arg_name="user_id",
        path_arg_optional=False,
        json_args=["name"],
        method="PUT",
        )

    set_client_fixed_ip = UnifiAPICall(
        """Add, modify or remove a fixed ip of a client device

        Args:
            user_id (str): ``_id`` value of the user for which the name is set
            fixed_ip (str): IP to attach, or None to remove IP
            network_id (str): network to attach
        """,
        "rest/user",
        path_arg_name="user_id",
        path_arg_optional=False,
        json_args=["fixed_ip", "network_id"],
        method="PUT",
        )

    # Functions for retreiving statistics

    stat_5minutes_site = UnifiAPICall(
        """Fetch site statistics with 5 minute granularity

        Args:
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 12 hours before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return

        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/5minutes.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_SITE_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_12hours,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_hourly_site = UnifiAPICall(
        """Fetch site statistics with 1 hour granularity

        Args:
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 7 days before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return

        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/hourly.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_SITE_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_daily_site = UnifiAPICall(
        """Fetch site statistics with 1 day granularity

        Args:
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 1 year before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return

        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/daily.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_SITE_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_1year,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_5minutes_aps = UnifiAPICall(
        """Fetch access point statistics with 5 minute granularity

        Args:
            mac (str): `optional` MAC access of single AP for which to fetch statistics
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 12 hours before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return
        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/5minutes.ap",
        json_args=[('mac', None),
                   ('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_AP_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_12hours,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_hourly_aps = UnifiAPICall(
        """Fetch access point statistics with 1 hour granularity

        Args:
            mac (str): `optional` MAC access of single AP for which to fetch statistics
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 7 yays before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return
        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/hourly.ap",
        json_args=[('mac', None),
                   ('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_AP_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_daily_aps = UnifiAPICall(
        """Fetch access point statistics with 1 day granularity

        Args:
            mac (str): `optional` MAC access of single AP for which to fetch statistics
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 1 year before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return
        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/daily.ap",
        json_args=[('mac', None),
                   ('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_AP_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_1year,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_5minutes_user = UnifiAPICall(
        """Fetch client device statistics with 5 minute granularity

        Args:
            mac (str): MAC access of client device for which to fetch statistics
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 12 hours before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return
        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/5minutes.user",
        json_args=['mac',
                   ('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_USER_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_12hours,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_hourly_user = UnifiAPICall(
        """Fetch client device statistics with 1 hour granularity

        Args:
            mac (str): MAC access of client device for which to fetch statistics
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 7 days before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return
        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/hourly.user",
        json_args=['mac',
                   ('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_USER_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_daily_user = UnifiAPICall(
        """Fetch client device statistics with 1 day granularity

        Args:
            mac (str): MAC access of client device for which to fetch statistics
            start (int): `optional` start of reporting period, as seconds in the Unix
                epoch. If not present defaults to 1 year before the end time
            end (int): `optional` end of reporting period, as seconds in the Unix epoch.
                If not present defaults to the current time.
            attrs (list): `optional` list of statistics to return
        Returns:
            List of dictionaries of statistics
        """,
        "stat/report/daily.user",
        json_args=['mac',
                   ('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_USER_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_1year,
                  fix_ensure_time_attrib,
                  fix_times_as_ms],
        )

    stat_sessions = UnifiAPICall(
        "Show login sessions",
        "stat/session",
        json_args=[('mac', None),
                   ('start', None),
                   ('end', None),
                   ('type', 'all')],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_enforce_values({'type':['all', 'guest', 'user']})],
        )

    stat_sta_sessions_latest = UnifiAPICall(
        "Show latest 'n' login sessions for a single client device",
        "stat/session",
        json_args=['mac',
                   ('limit', 5)],
        json_fix=[fix_constants({'_sort': '-assoc_time'}),
                  fix_arg_names({'limit': '_limit'})],
        )

    stat_auths = UnifiAPICall(
        "Show all authorizations",
        "stat/authorization",
        json_args=[('start', None),
                   ('end', None)],
        json_fix=[fix_end_now,
                  fix_start_7days],
        )

    list_allusers = UnifiAPICall(
        "List all client devices ever connected to the site",
        "stat/alluser",
        json_args=[('type', 'all'),
                   ('conn', 'all'),
                   ('within', 365 * 24)],
        )

    list_guests = UnifiAPICall(
        "List guest devices",
        "stat/guest",
        json_args=[('within', 365 * 24)],
        )

    list_clients = UnifiAPICall(
        "List currently connected client devices, or details on a single MAC address",
        "stat/sta",
        path_arg_name="client_mac",
        )

    list_configured_clients = UnifiAPICall(
        "List configured client devices, or details on a single MAC address",
        "rest/user",
        path_arg_name="client_mac",
        )

    get_client_details = UnifiAPICall(
        "Get details about a client",
        "stat/user",
        path_arg_name="client_mac",
        path_arg_optional=False,
        )

    list_usergroups = UnifiAPICall(
        "List user groups",
        "list/usergroup",
        )

    set_usergroup = UnifiAPICall(
        "Set the user group for a client",
        "upd/user",
        path_arg_name="client_mac",
        path_arg_optional=False,
        json_args=['usergroup_id'],
        method="PUT",
        )

    # FIXME: Is the site ID required here, or only needed if you want to change it?
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

    list_health = UnifiAPICall(
        "List health metrics",
        "stat/health",
        )

    #### Should probably support '?scale=5minutes'
    list_dashboard = UnifiAPICall(
        "List dashboard metrics",
        "stat/dashboard",
        )

    list_users = UnifiAPICall(
        "List knows clients groups",
        "list/user",
        )

    list_devices = UnifiAPICall(
        """List details of one or more managed device on this site

        Args:
            device_mac (str): `optional` MAC address of device on which to fetch details

        Returns:
            list of dictionaries of device details.
        """,
        "stat/device",
        path_arg_name="device_mac",
        )

    list_devices_basic = UnifiAPICall(
        """List basic information about all managed devices""",
        "stat/device-basic",
        )

    list_tags = UnifiAPICall(
        "List known device tags",
        "rest/tag",
        )

    list_rogueaps = UnifiAPICall(
        "List rogue or nearby APs",
        "stat/rogueap",
        json_args=[('within', 24)],
        )

    list_rogueknown = UnifiAPICall(
        "List rogue or nearby APs",
        "rest/rogueknown",
        )

    list_sites = UnifiAPICallNoSite(
        "List sites on this controller",
        "self/sites",
        )

    stat_sites = UnifiAPICallNoSite(
        "Get stats for sites on this controller",
        "stat/sites",
        )

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

    set_site_country = UnifiAPICall(
        "Set site country",
        "rest/setting/country",
        json_body_name="setting",
        method="PUT",
        )

    set_site_locale = UnifiAPICall(
        "Set site locale",
        "rest/setting/locale",
        json_body_name="setting",
        method="PUT",
        )

    set_site_snmp = UnifiAPICall(
        "Set site snmp",
        "rest/setting/snmp",
        json_body_name="setting",
        method="PUT",
        )

    set_site_mgmt = UnifiAPICall(
        "Set site mgmt",
        "rest/setting/mgmt",
        json_body_name="setting",
        method="PUT",
        )

    set_site_guest_access = UnifiAPICall(
        "Set site guest access",
        "rest/setting/guest_access",
        json_body_name="setting",
        method="PUT",
        )

    set_site_ntp = UnifiAPICall(
        "Set site ntp",
        "rest/setting/ntp",
        json_body_name="setting",
        method="PUT",
        )

    set_site_connectivity = UnifiAPICall(
        "Set site connectivity",
        "rest/setting/connectivity",
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

    invite_admin = UnifiAPICall(
        "Invite a new admin for access to the current site",
        "cmd/sitemgr",
        json_args=['name',
                   'email',
                   ('readonly', False),
                   ('enable_sso', True),
                   ('device_adopt', False),
                   ('device_restart', False)],
        rest_command='invite-admin',
        json_fix=[fix_arg_names({'enable_sso':'for_sso'}),
                  fix_admin_permissions,
                  fix_check_email('email')],
        )

    create_admin = UnifiAPICall(
        "Create a new admin user",
        "cmd/sitemgr",
        json_args=['name',
                  'email',
                  'password',
                  ('requires_new_password', False),
                  ('readonly', False),
                  ('enable_sso', True),
                  ('device_adopt', False),
                  ('device_restart', False)],
        rest_command='create-admin',
        json_fix=[fix_arg_names({'enable_sso':'for_sso', 'password': 'x_password'}),
                  fix_admin_permissions,
                  fix_check_email('email')],
        )

    revoke_admin = UnifiAPICall(
        "Revoke an admin user",
        "cmd/sitemgr",
        rest_command="revoke-admin",
        json_args=['admin'],
        )

    list_wlan_groups = UnifiAPICall(
        "List wlan_groups",
        "list/wlangroup",
        )

    stat_sysinfo = UnifiAPICall(
        "Show general system information",
        "stat/sysinfo",
        )

    stat_status = UnifiAPICallNoSite(
        "Get controller status",
        # Note the leading / since this is at the root level
        "/status",
        )

    list_self = UnifiAPICall(
        "Get info about the logged in user",
        "self",
        )

    list_vouchers = UnifiAPICall(
        "List vouchers",
        "stat/voucher",
        json_args=[('create_time', None)],
        )

    #### FIX ME: Should add support for 'within' parameter
    stat_payment = UnifiAPICall(
        "List payments",
        "stat/payment",
        )

    create_hotspotop = UnifiAPICall(
        "Create hotspot operator",
        "rest/hotspotop",
        json_args=['name',
                   'password',
                   'note'],
        json_fix=[fix_note_noted,
                  X_PASSWORD_FIX],
        )

    list_hotspotop = UnifiAPICall(
        "List hotspot operators",
        "rest/hotspotop",
        )

    create_voucher = UnifiAPICall(
        """
        Creates a voucher
    
        Args:
            minutes (int): expiration time in minutes
            expire_unit (int): 1440 - do not change, number of minutes in a day
            expire_number (int): 1 - do not change
            count (int): number of vouchers to create using these specs
            quota (int): number of uses, 0 is unlimited use
            up (int): bandwidth limit in mb
            down (int): bandwidth limit in mb
            bytes (int): constraint in mb
        Returns:
            {'create_time': epoch-time}
        """,
        "cmd/hotspot",
        rest_command="create-voucher",
        json_args=['minutes',
                   ('expire_unit', 1440),
                   ('expire_number', 1),
                   ('count', 1),
                   ('quota', 1),
                   ('note', None),
                   ('up', None),
                   ('down', None),
                   ('bytes', None)],
        json_fix=[fix_arg_names({'minutes': 'expire', 'count': 'n'})],
        )

    revoke_voucher = UnifiAPICall(
        "Revoke voucher",
        "cmd/hotspot",
        rest_command="delete-voucher",
        json_args=['voucher_id'],
        json_fix=[fix_arg_names({'voucher_id': '_id'})],
        )

    extend_guest_validity = UnifiAPICall(
        "Extend guest validity",
        "cmd/hotspot",
        rest_command="extend",
        json_args=['guest_id'],
        json_fix=[fix_arg_names({'guest_id':"_id"})],
        )

    list_portforward_stats = UnifiAPICall(
        "List port forwarding configuation and statistics",
        "stat/portforward",
        )

    list_vpn_stats =  UnifiAPICall(
        "List VPN users and statistics",
        "stat/remoteuservpn",
        )

    list_dpi_stats = UnifiAPICall(
        "List deep packet inspection stats",
        "stat/dpi",
        )

    list_current_channels = UnifiAPICall(
        "List currently available channels",
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
        path_arg_name='key',
        )

    enable_portforwarding_rule = UnifiAPICall(
        """Enable or disable a port forwarding rule

        Args:
            pfr_id (str): ``_id`` value of the portforwarding rule
            enabled (bool): true to enable the rule, false to disable the rule
        """,
        "rest/portforward",
        path_arg_name="pfr_id",
        path_arg_optional=False,
        json_args=["enabled"],
        method="PUT",
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
        "Disable/enable an access point",
        "rest/device",
        path_arg_name="ap_id",
        path_arg_optional=False,
        json_args=['disabled'],
        method="PUT",
        )

    led_override = UnifiAPICall(
        "Override LED mode for a device",
        "rest/device",
        path_arg_name="device_id",
        path_arg_optional=False,
        json_args=['led_override'],
        json_fix=[fix_enforce_values({"led_override": ['off', 'on', 'default']})],
        method="PUT",
        )

    locate_ap = UnifiAPICall(
        "Toggle flashing LED of an access point for locating purposes",
        "cmd/devmgr",
        json_args=['mac', 'enabled'],
        json_fix=[fix_locate_ap_cmd],
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
        json_args=['radio_table',
                   'channel',
                   'ht',
                   'tx_power_mode',
                   'tx_power'],
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
        path_arg_name="network_id",
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
        "Delete a network",
        "rest/networkconf",
        path_arg_name="network_id",
        path_arg_optional=False,
        method="DELETE",
        )

    list_wlanconf = UnifiAPICall(
        "List wireless LAN settings for all or one network",
        "rest/wlanconf",
        path_arg_name="wlan_id",
        )

    _raw_set_wlan_settings = UnifiAPICall(
        "Low-level function to set wireless LAN settings",
        "rest/wlanconf",
        path_arg_name="wlan_id",
        path_arg_optional=False,
        json_body_name="settings",
        method="PUT",
        )

    def set_wlan_settings(self, wlan_id, passphrase, ssid=None):
        """Set wireless LAN password and SSID"""
        settings = {"x_passphrase": passphrase}
        if ssid is not None:
            settings['name'] = ssid

        return self._raw_set_wlan_settings(wlan_id, settings=settings)

    def enable_wlan(self, wlan_id, enabled):
        """Enable or diabble a wireless LAN"""
        return self._raw_set_wlan_settings(wlan_id, {"enabled": bool(enabled)})

    def set_wlan_mac_filter(self, wlan_id, enabled, whitelist=False, mac_list=None):
        "Set wireless LAN MAC filtering policy"
        if mac_list is None:
            mac_list = []
        settings = {"mac_filter_enabled": enabled,
                    "mac_filter_policy": 'allow' if whitelist else 'deny',
                    "mac_filter_list": mac_list}
        return self._raw_set_wlan_settings(wlan_id, settings=settings)

    delete_wlan = UnifiAPICall(
        "Delete a wlan",
        "rest/wlanconf",
        path_arg_name="wlan_id",
        path_arg_optional=False,
        method="DELETE",
        )

    list_events = UnifiAPICall(
        """List events

        Args:
            historyhours (int): how far back to list events
            start (int): index of the first event to return
            limit (int): maximum number of events to return
        """,
        "stat/event",
        json_args=[('historyhours', 720),
                   ('start', 0),
                   ('limit', 1000)],
        json_fix=[fix_arg_names({'historyhours': 'within',
                                 'start': '_start',
                                 'limit': '_limit'}),
                  fix_constants({'_sort': '-time',
                                 'type': None})],
        )

    list_alarms = UnifiAPICall(
        "List all alarms",
        "list/alarm",
        )

    count_alarms = UnifiAPICall(
        "Count alarms",
        "cnt/alarm",
        )

    archive_alarm = UnifiAPICall(
        """Archive a single alarm""",
        "cmd/evtmgr",
        rest_command="archive-alarm",
        json_args=['alarm_id'],
        method="POST",
        json_fix=[fix_arg_names({'alarm_id':'_id'})],
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
        rest_command='power-cycle',
        json_args=['mac', 'port_idx'],
        )

    spectrum_scan = UnifiAPICall(
        "Trigger an RF scan by an AP",
        "cmd/devmgr",
        rest_command='spectrum-scan',
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
        path_arg_name="profile_id",
        )

    list_radius_accounts = UnifiAPICall(
        "List Radius user accounts",
        "rest/account",
        path_arg_name="account_id",
        )

    #### FIX ME: This needs documentation of the tunnel types
    create_radius_account = UnifiAPICall(
        "Create a Radius user account",
        "rest/account",
        json_args=['name',
                   'password',
                   'tunnel_type',
                   'tunnel_medium_type',
                   ('vlan', None)],
        json_fix=[X_PASSWORD_FIX],
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
        "Delete a Radius account",
        "rest/account",
        path_arg_name="account_id",
        path_arg_optional=False,
        method="DELETE",
        )
