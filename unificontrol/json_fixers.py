""" Functions in the ``unificontrol.json_fixers`` module are fixers to fix up JSON objects before posting to
the controller. This allows us to have cleaner function signatures
when the underlying API is a bit verbose.

All functions accept a JSON dictionary of existing attributes and return a modified
dictionary, which may or may not be the same object.
"""

import time
import re

EMAIL_RE = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

# pylint: disable=missing-docstring

def fix_note_noted(json):
    """Ensure the 'noted' flag is set if and only if a note is given"""
    if 'note' in json and json['note']:
        json['noted'] = True
    else:
        del json['note']
        json['noted'] = False
    return json

# Arguments for user creation sit deeper in the JSON structure.
def fix_user_object_nesting(json):
    return {"objects": [{"data":json}]}

def fix_macs_list(json):
    """Convert a single mac into a list as necessary"""
    if 'macs' in json and isinstance(json['macs'], str):
        json['macs'] = [json['macs']]
    return json

# Functions to fix start and end times

def fix_end_now(json):
    """Set end time to the time now if no end time is give"""
    if 'end' not in json or json['end'] is None:
        json['end'] = int(time.time())
    return json

# Set start time to end-delta is no start given
def fix_start_delta(json, delta):
    if 'start' not in json or json['start'] is None:
        json['start'] = json['end'] - delta
    return json

def fix_start_12hours(json):
    """Fix start to 12 hours before end if not given"""
    return fix_start_delta(json, 12 * 3600)

def fix_start_7days(json):
    """Fix start to 7 days before end if not given"""
    return fix_start_delta(json, 7 * 24 * 3600)

def fix_start_1year(json):
    """Fix start to 1 year before end if not given"""
    return fix_start_delta(json, 365 * 24 * 3600)

def fix_times_as_ms(json):
    """Adjust start and end times to be in milliseconds rather than seconds"""
    if 'start' in json:
        json['start'] = int(json['start'] * 1000)
    if 'end' in json:
        json['end'] = int(json['end'] * 1000)
    return json

def fix_ensure_time_attrib(json):
    """Ensure that requested attributes include the 'time' attribute"""
    if 'attrs' not in json:
        json['attrs'] = []
    if 'time' not in json['attrs']:
        json['attrs'].append('time')
    return json

def fix_constants(constants):
    """Given a dict of constant parameters this function returns a fixer
    function that updates the json to include these constants"""
    def fix_const_updater(json):
        json.update(constants)
        return json
    return fix_const_updater

def fix_arg_names(mapping):
    """Given a mapping, return a fixer that renames the json arguments
    listed in the mapping. For example:

    .. code:: python

        json_fix = [fix_arg_names({'enable_sso':'for_sso'})] # Let the user write ``enable_sso`` when the API wants ``for_sso``
    """
    def arg_name_fixer(json):
        for key in mapping:
            if key in json:
                json[mapping[key]] = json[key]
                del json[key]
        return json
    return arg_name_fixer

def fix_enforce_values(mapping):
    """Given a mapping create a fixer that checks the value in an argument and
    raises a (helpful) ValueError exception if the value is not one listed"""
    def arg_value_checker(json):
        for key in mapping:
            if key in json and json[key] not in mapping[key]:
                raise ValueError("value of {} argument must be one of {}".format(
                    key, mapping[key]))
        return json
    return arg_value_checker

# Choose which REST command to use depending on if we are enabling or disabiling
def fix_locate_ap_cmd(json):
    json['cmd'] = 'set-locate' if json['enabled'] else 'unset-locate'
    del json['enabled']
    return json

# Convert function arguments for admin creation into internal representation
def fix_admin_permissions(json):
    permissions = []
    if 'device_adopt' in json:
        if json['device_adopt']:
            permissions.append("API_DEVICE_ADOPT")
        del json['device_adopt']
    if 'device_restart' in json:
        if json['device_restart']:
            permissions.append("API_DEVICE_RESTART")
        del json['device_restart']
    if 'readonly' in json:
        if json['readonly']:
            json['role'] = 'readonly'
        del json['readonly']
        if permissions:
            json['permissions'] = permissions
    return json

def fix_check_email(field_name):
    """Given the name of a field return a fixer that check that that field is
    a valid email address"""
    def email_checker(json):
        email = json[field_name] = json[field_name].strip()
        if not EMAIL_RE.match(email):
            raise ValueError("'{}' does not look like a vaid email address".format(email))
        return json
    return email_checker
