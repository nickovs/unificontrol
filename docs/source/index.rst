Welcome to unificontrol's documentation!
========================================

unificontrol is a rich and full-featured Python interface to the
Ubiquiti Unifi software defined network controller. Goals of this package
include:

- A clean interface that supports introspection and self-documentation.
- A complete implementation of the Unifi controller API. Currently it supports over 100 API calls to the Unifi controller.
- Proper handling of SSL connections to allow secure access to the controller even when the controller uses a self-signed certificate.
- A concise, readable internal representation of the Unifi API, so that new API calls can easily be added as new features are added to the controller.
- Python 3 only, since it's the way of the future.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   Introduction <introduction>
   The unificontrol API <API>
   ssl_self_signed

         
Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
