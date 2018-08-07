A high-level Python interface to the Unifi controller software
==============================================================

unificontrol is a rich and full-featured Python interface to the
Ubiquiti Unifi software defined network controller. Goals of this package
include:

- A clean interface that supports introspection and self-documentation.
- A complete implementation of the Unifi controller API. Currently it supports over 100 API calls to the Unifi controller.
- Proper handling of SSL connections to allow secure access to the controller even when the controller uses a [self-signed certificate](ssl_self_signed.md).
- A concise, readable internal representation of the Unifi API, so that new API calls can easily be added as new features are added to the controller.
- Python 3 only, since it's the way of the future.

Installation
------------

To install the most recent release use:
::

  pip install unificontrol

To install the latest version of the code from GitHub use:

::

  pip install -e git+https://github.com/nickovs/unificontrol.git@master#egg=unificontrol

Documentation
-------------

The `unificontrol` code aims to be self-documenting as far as possible so if you are using it in an interactive environment the built in Python `help()` function will often tell you what you need.

There is also documentation that can be built using Sphynx in the `docs` directory and a built version of these docs is `hosted on ReadTheDocs <https://unificontrol.readthedocs.io/en/latest/>`_.

.. --- PyPI STOP ---


Usage
-----

The simplest way to use this client is simply to create an instance with the necessary parameters and log in:

.. code:: python

    client = UnifiClient(host="unifi.localdomain",
        username=UNIFI_USER, password=UNIFI_PASSWORD, site=UNIFI_SITE)


The host name (and the host port, if you are using something other than the default 8443) must be specificed when you create the client. The username and password can be passed to the login method instead of the contstructor if you prefer. If you supply then username and password in the constructor then the client will automatically log in when needed and re-authenticate if your
session expires.

Once you have created a client object you can simply make calls to the various API endpoints on the controler:

.. code:: python

    # Get a list of all the guest devices for the last day
    guests = client.list_guests(within=24)

    # Upgrade one of the access points 
    client.upgrade_device("11:22:33:44:55:66")


See the :any:`API documentation <API>` for full details.
    

Support for self-signed certificates
------------------------------------

Since the Unifi controller uses a :any:`self-signed certifcate <ssl_self_signed>` the default behaviour of the client is to fetch the SSL certificate from the server when you create the client instance and pin all future SSL connections to require the same certificate. This works OK but if you are building some tool that will talk to the controller and you have place to store configuration then a better solution is to store a copy of the correct certificate in a safe place and supply it to the constructor using the `cert` keyword argument. A server's certifcate can be fetched using the python ssl library:

.. code:: python

    import ssl
    cert = ssl.get_server_certificate(("unifi.localdomain", 8443))
    # Store the cert in a safe place
    ...
    # Fetch the cert from a safe place
    client = UnifiClient(host="unifi.localdomain",
        username=UNIFI_USER, password=UNIFI_PASSWORD, site=UNIFI_SITE,
        cert=cert)

If you have a proper certificate for the controller, issued by a known authority and with a subject name matching the host name used to access the server then you can switch off the certificate pinning by passing ``cert=None``.


Acknowledgments
---------------

I would almost certainly never have written such a complete implementation of the API had it not been for the hard work done by the authors of the PHP `Unifi API client <https://github.com/Art-of-WiFi/UniFi-API-client>`_ created by `Art of WiFi <https://artofwifi.net>`_. While the code here was written from scratch, all of the necessary analysis and understanding of the undocumented API was taken from the PHP client. Without that open source project I would probably have stopped with less than a quarter of the API finished.
