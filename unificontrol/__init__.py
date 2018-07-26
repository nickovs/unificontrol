# unificontrol

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

# pylint: disable=invalid-name

"""unificontrol

unificontrol allows for control of the Ubiquiti Unifi software defined network
controller. It offers a pythonic interface, automatic session handling, SSL
certificate pinning and interface introspection.
"""

from .unifi import UnifiClient
from .exceptions import UnifiError, UnifiAPIError, UnifiTransportError, UnifiLoginError

name = "unificontrol"
