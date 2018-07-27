# A high-level Python interface to the Unifi controller software

unificontrol aims to be a rich and full-featured Python interface to the
Ubiquiti Unifi software defined network controller. Goals of this package
include:
* A clean interface that supports introspection and self-documentation.
* Proper handling of SSL connections to allow secure access to the controller even if it uses a self-signed certificate.
* A concise, readable internal representation of the Unifi API so that new API calls can easily be added as new features are added to the controller.
* Python 3 only, since it's the way of the future.

## Installation

```
pip install -e git+https://github.com/nickovs/unificontrol.git@master#egg=unificontrol
```

## Usage

```
client = UnifiClient(host="unifi.localdomain", username=UNIFI_USER, password=UNIFI_PASSWORD, site=UNIFI_SITE)
```


## SSL Security with self-signed certificates

The Unifi controller is accessed using the `https:` protocol in order protect the session. Unfortunately the way that they do this does no protect against _Man-In-The-Middle_ attacks due to the use of a _self-signed certificate_. To understand why this is an issue and how to fix it it is necessary to understand a bit about whhat SSL certificates do and how they do it.

The SSL protocol (and its more modern successor, the TLS protocol) make use of _digital certificates_. These are esentially messages that are a digitally _signed_ message _signed_ by some party to state that a particular identiry is connected to a particular _public key_. A _public key_ is a value that can be used to verify a _digital signature_ such as the ones on these certificates. Each certificate has an _issuer_, the party signing the message, and a _subject_, the party that is having its identity/key relationship asserted in this certificate. In order to validate a certificate you need to have a copy of the _public key_ associated with the _issuer_. The _public key_ belonging to the _subject_ of the certificate that is sent in the course of starting an SSL session is used to validate _digital signatures_ in the SSL handshake messages and this is used as evidence that the server with which you are communicating belongs to the _subject_ of the certificate.

When you make an SSL connection on the internet it is typical for the server at the other end to have a _certificate_ issued by some well know authority. Your web browser has the public keys of many well know authorities built in to it. In these certificates the identity of the _subject_ includes the domain name of the server t which you are connecting and these authorities are supposed to only issue certifcate to the owners of the domains. This way you can have confondence that you are connecting to the right server and not to some system that is trying to eavesdrop on yout conversation.

The Unifi controller (and many other local servers and appliances) typically  does not have a public, externally accessable domain name and even if it did, getting a certificate for that domain name is often time consuming and expensive. As a result wha Ubiquiti (along with most appliance vendors) do is to create a _self-signed certificate_. This is a certificate for which the _issuer_ is not some well known authority but is instead the same identity as the _subject_. The first time you fire up the Unifi controller it spots that it doesn't have a certificate and creates a new one, signed by itself, and identifying the server with the host name `unifi`.

There are two problems with this approach. Firstly since the _issuer_ of the certificate is not a well known authority many systems will that the certificate is issued by an unknown party. Secondly, unless you access your Unifi controller using the unqualified domain name `unifi` the host name in the certificate will not match the host name used to access the server and again the system will complain about a mismatched domain name. Furthermore, since the certificate was just created out of thin air, if you anticipate and ignore these two warnings then there is nothing to stop an eavesdropper from simply creating a new _self-signed certificate_ and fooling you into sending your credentials to a bogus server instead of the Unifi controller.

Fortunately there is a solution to these problems. The solution is known as _certificate pinning_. This basically just means that you expect to see the same certificate every time you access the same server. This won't help if the eavedropper is already intercepting your connections the first time you access a service but it will protect you for all subsequent accesses.

This library supports certificate pinning.

