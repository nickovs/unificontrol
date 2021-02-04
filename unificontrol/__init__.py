# unificontrol

# Copyright 2018-2021 Nicko van Someren
#
# Licensed under the Apache License, Version 2.0 (the "License")
# See the LICENSE.txt file for details

# SPDX-License-Identifier: Apache-2.0

# pylint: disable=invalid-name

"""unificontrol

unificontrol allows for control of the Ubiquiti Unifi software defined network
controller. It offers a pythonic interface, automatic session handling, SSL
certificate pinning and interface introspection.
"""

__version__ = "0.3.0"

from .unifi import UnifiClient, FETCH_CERT
from .exceptions import UnifiError, UnifiAPIError, UnifiTransportError, UnifiLoginError
from .constants import RadiusTunnelType, RadiusTunnelMediumType, UnifiServerType

name = "unificontrol"
