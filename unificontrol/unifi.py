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
                          fix_admin_permissions)
from .pinned_requests import PinningHTTPSAdapter

# Indicate that the client should fetch the server's SSL certificate
FETCH_CERT = "FETCH_CERT"

# Default lists of stats to return for various stat calls
_DEFAULT_SITE_ATTRIBUTES = ['bytes', 'wan-tx_bytes', 'wan-rx_bytes',
                            'wlan_bytes', 'num_sta', 'lan-num_sta',
                            'wlan-num_sta', 'time']
_DEFAULT_AP_ATTRIBUTES = ['bytes', 'num_sta', 'time']
_DEFAULT_USER_ATTRIBUTES = ['time', 'rx_bytes', 'tx_bytes']

# The main Unifi client object

class UnifiClient(metaclass=MetaNameFixer):
    # pylint: disable=too-many-instance-attributes, too-many-arguments
    """An abstract interface to the Unifi controller"""

    def __init__(self, host="localhost", port=8443,
                 username="admin", password=None, site=None,
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
            resp = ses.send(ses.prepare_request(request), verify=self._verify)

        if resp.ok:
            response = resp.json()
            if 'meta' in response and response['meta']['rc'] != 'ok':
                raise UnifiAPIError(response['meta']['msg'])
            return response['data']
        else:
            raise UnifiTransportError("{}: {}".format(resp.status_code, resp.reason))

    @property
    def host(self):
        """Host name of contoller"""
        return self._host

    @property
    def port(self):
        """Port for accessing controller"""
        return self._port

    @property
    def site(self):
        """Identifier of site being managed"""
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
        rest_command="authorize-guest",
        json_args=["mac",
                   "minutes",
                   ("up", None),
                   ("down", None),
                   ("MBytes", None),
                   ("ap_mac", None)],
        )

    unauthorize_guest = UnifiAPICall(
        "Unauthorize a client device",
        "cmd/stamgr",
        rest_command="unauthorize-guest",
        json_args=["mac"],
        )

    reconnect_client = UnifiAPICall(
        "Force reconnection of a client device",
        "cmd/stamgr",
        rest_command="kick-sta",
        json_args=["mac"],
        )

    block_client = UnifiAPICall(
        "Block a client device",
        "cmd/stamgr",
        rest_command="block-sta",
        json_args=["mac"],
        )

    unblock_client = UnifiAPICall(
        "Unblock a client device",
        "cmd/stamgr",
        rest_command="unblock-sta",
        json_args=["mac"],
        )

    forget_client = UnifiAPICall(
        "Forget a client device",
        "cmd/stamgr",
        rest_command="forget-sta",
        json_args=["macs"],
        json_fix=[fix_macs_list],
        )

    create_client = UnifiAPICall(
        "Creat a new user/client device",
        "group/user",
        json_args=["mac",
                   "usergroup_id",
                   ("name", None),
                   ("note", None)],
        json_fix=[fix_note_noted, fix_user_object_nesting],
        )

    set_client_note = UnifiAPICall(
        "Add, modify or remove a note on a client device",
        "upd/user",
        path_arg_name="user_id",
        path_arg_optional=False,
        json_args=["note"],
        json_fix=[fix_note_noted],
        method="PUT",
        )

    set_client_name = UnifiAPICall(
        "Add, modify or remove a name on a client device",
        "upd/user",
        path_arg_name="user_id",
        path_arg_optional=False,
        json_args=["name"],
        method="PUT",
        )

    # Functions for retreiving statistics

    stat_5minutes_site = UnifiAPICall(
        "5 minutes site stats method",
        "stat/report/5minutes.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_SITE_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_12hours,
                  fix_ensure_time_attrib],
        )

    stat_hourly_site = UnifiAPICall(
        "Hourly site stats method",
        "stat/report/hourly.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_SITE_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_ensure_time_attrib],
        )

    stat_daily_site = UnifiAPICall(
        "Daily site stats method",
        "stat/report/daily.site",
        json_args=[('start', None),
                   ('end', None),
                   ('attrs', _DEFAULT_SITE_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_1year,
                  fix_ensure_time_attrib],
        )

    stat_5minutes_aps = UnifiAPICall(
        "5 minutes stats method for a single access point or all access points",
        "stat/report/5minutes.ap",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _DEFAULT_AP_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_12hours,
                  fix_ensure_time_attrib],
        )

    stat_hourly_aps = UnifiAPICall(
        "Hourly stats method for a single access point or all access points",
        "stat/report/hourly.ap",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _DEFAULT_AP_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_ensure_time_attrib],
        )

    stat_daily_aps = UnifiAPICall(
        "Daily stats method for a single access point or all access points",
        "stat/report/daily.ap",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _DEFAULT_AP_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_1year,
                  fix_ensure_time_attrib],
        )

    stat_5minutes_user = UnifiAPICall(
        "5 minutes stats method for a single user/client device",
        "stat/report/5minutes.user",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _DEFAULT_USER_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_12hours,
                  fix_ensure_time_attrib],
        )

    stat_hourly_user = UnifiAPICall(
        "Hourly stats method for a a single user/client device",
        "stat/report/hourly.user",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _DEFAULT_USER_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_7days,
                  fix_ensure_time_attrib],
        )

    stat_daily_user = UnifiAPICall(
        "Daily stats method for a single user/client device",
        "stat/report/daily.user",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('attrs', _DEFAULT_USER_ATTRIBUTES)],
        json_fix=[fix_end_now,
                  fix_start_1year,
                  fix_ensure_time_attrib],
        )

    stat_sessions = UnifiAPICall(
        "Show all login sessions",
        "stat/session",
        json_args=[('start', None),
                   ('end', None),
                   ('mac', None),
                   ('type', 'all')],
        json_fix=[fix_end_now,
                  fix_start_7days],
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

    get_client_details = UnifiAPICall(
        "Get details about a client",
        "stat/user",
        path_arg_name="client_mac",
        path_arg_optional=False,
        )

    list_usergroups = UnifiAPICall(
        "List user groups",
        "list/usergroup")

    set_usergroup = UnifiAPICall(
        "Set the user group for a client",
        "upd/user",
        path_arg_name="client_mac",
        path_arg_optional=False,
        json_args=['usergroup_id'],
        method="PUT",
        )

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

    list_health = UnifiAPICall(
        "List health metrics",
        "stat/health")

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
        "List managed devices on this site",
        "stat/devices",
        path_arg_name="device_mac",
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
        json_fix=[fix_note_noted],
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

    revoke_voucher = UnifiAPICall(
        "Revoke voucher",
        "cmd/hotspot",
        rest_command="delete-voucher",
        json_args=['voucher_id'],
        json_fix=[fix_arg_names({'voucher_id':"_id"})],
        )

    extend_guest_validity = UnifiAPICall(
        "Extend guest validity",
        "cmd/hotspot",
        rest_command="extend",
        json_args=['guest_id'],
        json_fix=[fix_arg_names({'guest_id':"_id"})],
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

    led_override = UnifiAPICall(
        "Override LED mode for a device (using REST)",
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
        "Delete a wlan (using REST)",
        "rest/wlanconf",
        path_arg_name="wlan_id",
        path_arg_optional=False,
        method="DELETE",
        )

    list_events = UnifiAPICall(
        "List events",
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
        )

    list_radius_accounts = UnifiAPICall(
        "List Radius user accounts",
        "rest/account",
        )

    #### FIX ME: This needs documentation of the tunnel types
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
