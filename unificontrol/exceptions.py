# Copyright 2018-2021 Nicko van Someren
#
# Licensed under the Apache License, Version 2.0 (the "License")
# See the LICENSE.txt file for details

# SPDX-License-Identifier: Apache-2.0

"""Exceptions that can be raised by the Unifi client"""

# An heirarchy of exceptions for our error conditions.
class UnifiError(Exception):
    "General errors from the library"

class UnifiAPIError(UnifiError):
    "Error returned from the Unifi controller"

class UnifiTransportError(UnifiError):
    "Error talking to the Unifi controller"

class UnifiLoginError(UnifiError):
    "Bad user name or password"
