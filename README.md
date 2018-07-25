# A high-level Python interface to the Unifi controller software

unificontrol aims to be a rich and full-featured Python interface to the
Ubiquiti Unifi software defined network controller. Goals of this package
include:
* A clean interface that supports introspection and self-documentation.
* Proper handling of SSL connections to allow secure access to the controller even if it uses a self-signed certificate.
* A concise, readable internal representation of the Unifi API so that new API calls can easily be added as new features are added to the controller.

## Usage

```
client = UnifiClient(host="unifi.localdomain", username=UNIFI_USER, password=UNIFI_PASSWORD, site=UNIFI_SITE)
```

