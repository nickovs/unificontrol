"""Exceptions that can be raised by the Unifi client"""

# An heirarchy of exceptions for our error conditions.
class UnifiError(Exception):
    "General errors from the library"
    pass

class UnifiAPIError(UnifiError):
    "Error returned from the Unifi controller"
    pass

class UnifiTransportError(UnifiError):
    "Error talking to the Unifi controller"
    pass

class UnifiLoginError(UnifiError):
    "Bad user name or password"
    pass
