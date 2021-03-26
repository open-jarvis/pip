#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import hashlib
import random
from OpenSSL import crypto, SSL
from jarvis import Config
import ssl
import time


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
        Returns the PEM string representation of the key
        """
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
    def ssh_context():
        config = Config()
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        crt = f"/{config.get('directories')['root']}/jarvis-tmp-1-{time.time()}"
        pk  = f"/{config.get('directories')['root']}/jarvis-tmp-2-{time.time()}"
        with open(crt, "w") as f: f.write(config.get("certificate"))
        with open(pk,  "w") as f: f.write(config.get("private-key"))

        context.load_cert_chain(crt, pk)
        return context

