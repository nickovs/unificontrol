Extending the Unifi API
=======================

Ubiquiti are constantly enhancing the Unifi controller and each new release adds new functionality. As such new functionality will need to be added to this library as time goes by. Part of the design goal of this library was to make the addition of new API calls as simple as possible.

Metaprogramming
---------------

The main :class:`unificontrol.UnifiClient` class implements the more than 100 API calls to read and change settings on the controller. The vast majority of these calls map directly to a single https access to a specific endpoint on the Unifi controller web service. In order to avoid a great deal of repetition and `boilerplate code <https://en.wikipedia.org/wiki/Boilerplate_code>`_ each of these calls is created using `metaprogramming <https://en.wikipedia.org/wiki/Metaprogramming>`_; rather than writing code to implement each one, the functions are instead described at a high level and the details are created when the class is first loaded.

There are several advantages to using metaprogramming in this stiuation. Chief among these are:

* The nature and the intent of the function are easier to see, since there is less extraneous text.
* There is less code overall, which reduces the space for bugs to creep in (and also reduces finger fatigue).
* There is a great deal less repetition, which makes refactoring easier.
* Separating the specification from the implementation makes it easier to change either one.

Of course all of these aid with the main goal of making it easy to add new API calls when the controller gets enhancements.

Implementing API calls
----------------------

Most of the API calls in the :class:`unificontrol.UnifiClient` class are implemented simply by passing a description of the API call to an internal function called `UnifiAPICall` which constructs the necessary function call. For example the :meth:`list_alarms <unificontrol.UnifiClient.list_alarms>` method is implemented with the following code:

.. code:: python

    list_alarms = UnifiAPICall(
        "List all alarms",
        "list/alarm",
        )

In this example we only pass the two required parameters to `UnifiAPICall`, a documentation string and part of the path to the HTTP endpoint for th API call on the server. Of course for many API calls there are parameters that need to be passed. For instance, you can fetch details about managed Unifi devices using the :meth:`list_devices <unificontrol.UnifiClient.list_devices>` method and in this case you may optionally specify the MAC address of the managed device on the URL used to connect to the controller. When that is the case we can specify a name to give to a parameter for the extra componenet to be added to the URL in this case ``device_mac``:

.. code:: python

    list_devices = UnifiAPICall(
        """List details of one or more managed device on this site

        Args:
            device_mac (str): `optional` MAC address of device on which to fetch details

        Returns:
            list of dictionaries of device details.
        """,
        "stat/device",
        path_arg_name="device_mac",
        )

Often we want to pass a bunch of setting to the controller and these are usually sent by POSTing a JSON object containing the settings. Consider the case of the :meth:`edit_usergroup <unificontrol.UnifiClient.edit_usergroup>` method:

.. code:: python

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

Here the use must specify the ``group_id`` that is being edited (and since this is a requirement we set ``path_arg_optional`` to ``False`` to ensure that the user knows it's required). We also need to pass some arguments in the JSON object to set the ``site_id``, the ``name`` of the group and optionally bandwidth limits for upstream and downstream traffic. These are descibed in the ``json_args`` list; the first two (required) entries justy have names but for the last two we pass a tuple of ``(name, default)`` (the controller interprets the a value of -1 for either of these last two as unlimited). In this example we also see that this endpoint expects the configuration to be delivered in an HTTP PUT, rather than a POST, so we also provide a ``method`` value.

In some cases an HTTP endpoint is used to implement multiple operations, in which case the operation itself is also specified in the JSON payload. In this case you need to also need to specify the ``rest_command`` that will be passed as part of the JSON payload:

.. code:: python

    revoke_admin = UnifiAPICall(
        "Revoke an admin user",
        "cmd/sitemgr",
        rest_command="revoke-admin",
        json_args=['admin'],
        )

Sometimes the raw JSON arguments expected by the controller have names that are not very descriptive. Sometimes they take only certain values and it would be helpful to do some value checking. Sometimes we would like to pass default values that are not constants but are more context-sensitive. Sometimes we want to set hidden parameters based on the specified parameters. In all of these cases what we really need to do is filter the JSON arguments dictionary before we pass it to the controller. To do this we can use the ``json_fix`` argument. For example:

.. code:: python

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

Here we apply several fixer functions (in order). The first renames the argument ``enable_sso`` to the slightly more esoteric internal name ``for_sso``, the second converts some flag paramters to an internal dictionary representation used for the admin permissions and the third ensures that the ``email`` parameter contains a valid email address.

See the :ref:`json-fixup-label` section for a list of the current JSON fix-up functions.


For some of the operations, particularly for setting site-wide and network-specific settings, it makes more sense for the Python API to accept a dictionary of values to pass as the JSON request body rather than taking a large number of method arguments. In this case you can use the ``json_body_name`` arguement to set the name of the method argument under which this JSON value will be provided to the API.

.. code:: python

    set_site_snmp = UnifiAPICall(
        "Set site snmp",
        "rest/setting/snmp",
        json_body_name="setting",
        method="PUT",
        )

Most of the calls in the API apply to the settings for just one of the sites under management but a few apply to the controller as a whole. In these cases the method is created using ``UnifiAPICallNoSite`` instead of ``UnifiAPICall``. Also, so the few calls that do not require the user to be logged in you may pass ``need_login=False`` to indicate that the client object does not need to automatically log the user in and authentication failures should not trigger a login attempt.


.. _json-fixup-label:

JSON fix-up methods
-------------------

.. automodule:: unificontrol.json_fixers
   :members:
