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
