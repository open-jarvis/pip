"""
Copyright (c) 2021 Philipp Scheer
"""


import ssl
import time
import random
import hashlib
import hashlib, binascii, os
from jarvis import Config


class Security:
    """
    A Security class that provides hashing and id functions
    """
    @staticmethod
    def password_hash(pwd: str):
        """
        Hash a given password string using SHA512
        """
        return hashlib.sha512(pwd.encode("utf-8")).hexdigest()

    @staticmethod
    def id(len: int = 32, begin: str = "") -> str:
        """Generate a random id  
        `len` specifies the length of the id, this can also be a `str`:  
        * `micro`    = 8  
        * `mini`     = 16  
        * `small`    = 32  
        * `medium`   = 68  
        * `large`    = 128  
        * `critical` = 256
        """
        if isinstance(len, str):
            try:
                len = {
                    "micro": 8,
                    "mini": 16,
                    "small": 32,
                    "medium": 64,
                    "large": 128,
                    "critical": 256
                }[len]
            except KeyError:
                len = 32
        return begin + ''.join(random.choice("0123456789abcdef") for _ in range(len))

    @staticmethod
    def certificate(keylen: int = 4096,
                    emailAddress="emailAddress",
                    commonName="commonName",
                    countryName="NT",
                    localityName="localityName",
                    stateOrProvinceName="stateOrProvinceName",
                    organizationName="organizationName",
                    organizationUnitName="organizationUnitName",
                    serialNumber=0,
                    validityStartInSeconds=0,
                    validityEndInSeconds=10*365*24*60*60):
        """
        Generate a RSA key with `len` bitlength  
        Returns a PEM certificate and private-key:
        ```python
        {
            "certificate": ... PEM representation of the certificate ...,
            "private-key": ... PEM representation of the private-key ...
        }
        ```
        """
        from OpenSSL import crypto, SSL
        #can look at generated file using openssl:
        #openssl x509 -inform pem -in selfsigned.crt -noout -text
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, keylen)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        return {
            "certificate": crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"),
            "private-key": crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")
        }

    @staticmethod
    def get_server_certificate_and_ca(  keylen=4096, 
                                        caCommonName="jarvis", 
                                        commonName="jarvis", 
                                        crtFile="ca.crt", 
                                        keyFile="ca.key", 
                                        clientCrtFile="client.crt", 
                                        clientKeyFile="client.key"):
        from OpenSSL import crypto
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, keylen)

        ca_cert = crypto.X509()
        ca_cert.set_version(2)
        ca_cert.set_serial_number(random.randint(50000000,100000000))

        ca_subj = ca_cert.get_subject()
        ca_subj.commonName = caCommonName

        ca_cert.add_extensions([
            crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca_cert),
        ])

        ca_cert.add_extensions([
            crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca_cert),
        ])

        ca_cert.add_extensions([
            crypto.X509Extension("basicConstraints", False, "CA:TRUE"),
            crypto.X509Extension("keyUsage", False, "keyCertSign, cRLSign"),
        ])

        ca_cert.set_issuer(ca_subj)
        ca_cert.set_pubkey(ca_key)

        ca_cert.gmtime_adj_notBefore(0) # now
        ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # 10 years

        ca_cert.sign(ca_key, 'sha256')

        # Save certificate
        with open(crtFile, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

        # Save private key
        with open(keyFile, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

        client_key = crypto.PKey()
        client_key.generate_key(crypto.TYPE_RSA, keylen)

        client_cert = crypto.X509()
        client_cert.set_version(2)
        client_cert.set_serial_number(random.randint(50000000,100000000))

        client_subj = client_cert.get_subject()
        client_subj.commonName = commonName

        client_cert.add_extensions([
            crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
            crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=client_cert),
        ])

        client_cert.add_extensions([
            crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca_cert),
            crypto.X509Extension("extendedKeyUsage", False, "clientAuth"),
            crypto.X509Extension("keyUsage", False, "digitalSignature"),
        ])

        client_cert.set_issuer(ca_subj)
        client_cert.set_pubkey(client_key)

        client_cert.gmtime_adj_notBefore(0) # now
        client_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # 10 years

        client_cert.sign(ca_key, 'sha256')

        # Save certificate
        with open(clientCrtFile, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert))

        # Save private key
        with open(clientKeyFile, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key))

    @staticmethod
    def ssh_context() -> ssl.SSLContext:
        """
        Return a ssl.SSLContext containing the certificate and private key from database
        """
        config = Config()
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        crt = f"/{config.get('directories')['root']}/jarvis-tmp-1-{time.time()}"
        pk  = f"/{config.get('directories')['root']}/jarvis-tmp-2-{time.time()}"
        with open(crt, "w") as f: f.write(config.get("certificate"))
        with open(pk,  "w") as f: f.write(config.get("private-key"))

        context.load_cert_chain(crt, pk)
        return context
