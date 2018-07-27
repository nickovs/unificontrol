#!/usr/bin/env python3
"""Pinned certificate support for the requests library"""

# pylint: disable=invalid-name, import-error

import base64
import tempfile
import hashlib

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


BEGIN_CERT = '-----BEGIN CERTIFICATE-----'
END_CERT = '-----END CERTIFICATE-----'

# Simple conversions between PEM and DER format
def _PEM_to_DER(cert_pem):
    return base64.b64decode(cert_pem.split("-----")[2].strip())

def _cert_as_DER(cert):
    return _PEM_to_DER(cert) if "-----" in cert else cert

def _DER_to_PEM(cert_der):
    b64 = base64.b64encode(cert_der).decode("ASCII")
    chunks = [b64[i:i+64] for i in range(0, len(b64), 64)]
    chunks = [BEGIN_CERT] + chunks + [END_CERT, ""]
    return '\n'.join(chunks)

def _cert_as_PEM(cert):
    return _DER_to_PEM(cert) if "-----" not in cert else cert

def _cert_fingerprint(cert):
    """Returns the hex string of the cert fingerprint"""
    return hashlib.sha1(_cert_as_DER(cert)).digest().hex()


# This adaptor is just like a regular HTTPS adaptor except that it
# will only allow you to connect to a server that authenticates with a
# specific certificate. If that certificate is self-signed then this
# is all that is needed; if it is not self-signed then it also
# requires the certificate of the CA that issued the server cert.

class PinningHTTPSAdapter(HTTPAdapter):
    '''An HTTPS Transport Adapter that uses certificate pinning.

    Usage:
    >>> session = requests.session()
    >>> pinned_adaptor = PinningHTTPSAdapter(my_cert)
    >>> session.mount("https://myserver.example.com:443", pinned_adaptor)
    '''
    def __init__(self, cert, ca_cert=None, **kwargs):
        """cert is the server certificate to be pinned. ca_cert, if present, is the
        certificate of the authority that issued the server certificate (not needed
        for self-signed certs)"""
        if ca_cert is None:
            ca_cert = cert
        # The temporary file will be cleaned up when this adaptor is garbage collected
        self._ca_cert_temp = tempfile.NamedTemporaryFile(mode="w", suffix=".pem")
        self._ca_cert_temp.write(_cert_as_PEM(ca_cert))
        self._ca_cert_temp.flush()
        self._cert_fingerprint = _cert_fingerprint(cert)
        super(PinningHTTPSAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        """initialise the PoolManager with the pinned fingerprint"""
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ca_certs=self._ca_cert_temp.name,
                                       assert_fingerprint=self._cert_fingerprint,
                                       **pool_kwargs
                                      )

    def cert_verify(self, conn, url, verify, cert):
        """Force verification to be against our issuing authority"""
        super(PinningHTTPSAdapter, self).cert_verify(conn, url, self._ca_cert_temp.name, cert)
