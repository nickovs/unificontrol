The unificontrol API
====================

Interaction with Unifi controllers is done by creating an instance
of :class:`unificontrol.UnifiClient`. The methods of this class
represent calls to the various APIs exposed by the controller.

Data types
----------

Most of the data types used in the API are fairly self-explanitory. There are
however a few cases where some explaination is necessary.


ID values
*********

In many of the API calls various entities such as networks, user groups, managed
devices or other items are referred to by an ID value. In most cases these are 24
character unique hexadecimal strings which bear no relation to the visible names
of these objects. In these cases you will need to use the various ``list_...``
methods to get lists of the available objects and use the ``_id`` attribute from the
object you need.


Settings dictionaries
*********************

Many of the ``set_site_...`` calls take a ``settings`` dictionary.
In these case the :meth:`list_settings <unificontrol.UnifiClient.list_settings>`
method can be used to find the current settings object and thus determine the
keys expected in the settings dictionary.

.. Note::
   The settings dictionary should NOT contain an entry with the key ``_id`` as
   this will be automatically assigned. You should also remove the entry with
   the key ``key`` as this will be set to internally to refect the type of
   site setting to be set.


The UnifiClient class
---------------------

.. autoclass:: unificontrol.UnifiClient
   :members:
   :member-order: bysource

Constants
---------

.. autoclass:: unificontrol.RadiusTunnelType
   :members:
   :member-order: bysource

.. autoclass:: unificontrol.RadiusTunnelMediumType
   :members:
   :member-order: bysource

.. autoclass:: unificontrol.UnifiServerType
   :members:
   :member-order: bysource
