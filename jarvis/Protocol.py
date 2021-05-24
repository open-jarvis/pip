"""
Copyright (c) 2021 Philipp Scheer
"""


import json
import base64
from jarvis.Logger import Logger
from jarvis.Crypto import Crypto


logger = Logger("Protocol")


class Protocol:
    """Specifications of the Jarvis Message Protocol which is used to transfer messages in a secure way.  
    This class wraps the [`Crypto`](../classes/Crypto) class"""

    PUBKEY_START_SEQ = "-----BEGIN RSA PUBLIC KEY-----"
    """The starting sequence of a public RSA key"""

    VERSION = 1
    """Jarvis Message Protocol version number"""

    def __init__(self, local_private_key: str, local_public_key: str, remote_public_key: str = None, aes_key: bytes = None, aes_iv: bytes = None, auto_rotate: bool = True) -> None:
        """Wrapper class for secure communication  
        
        Usage: 
        ```python
        proto = Protocol(my_private_key, my_public_key, client_public_key, auto_rotate=True)
        encrypted: str = proto.encrypt({"this": "is", "a": "test"}, is_json=True)
        decrypted: str = proto.decrypt(encrypted, ignore_invalid_signature=False)
        ```
        Because we did not specify an AES key and IV, the Protocol automatically generates one for us  
        When setting `auto_rotate` to `True`, the AES key and IV are being changed after every message.
        This might slow down communication when sending a lot of information in a short amount of time:  
        ```
        | N pairs of AES key/iv | Time consumption |
        |-----------------------|------------------|
        |                 1,000 |            0.01s |
        |                10,000 |            0.10s |
        |               100,000 |            1.00s |
        ```
        """
        self.priv = local_private_key
        self.pub = local_public_key
        self.rpub = remote_public_key
        self.key = aes_key
        self.iv = aes_iv
        self.rotate = auto_rotate

        self.secure = False
        if self.rpub is not None and self.rpub.startswith(Protocol.PUBKEY_START_SEQ):
            self.secure = True

        if aes_key is None or aes_iv is None:
            self.rotate_aes()

    def encrypt(self, message: object, is_json: bool = True) -> str:
        """Encrypt a message using a symmetric key, sign the message and encrypt the symmetric key using RSA  
        How does it work?
        1. Check if message is a string. If not, apply `json.dumps`
        2. Convert message to bytes
        3. Is public key of client available?
            * Yes: encrypted messages
                1. Sign message using private key
                2. Encrypt message using AES
                3. AES key is encrypted using RSA
            * No: unencrypted messages
                1. Store the raw data
        4. All data is encoded using base64 and packed into a JSON object

        Returns:
        ```python
        >>> encrypt('{"this": "is", "a": "test"}', is_json=True)
        {
            "version": 1,
            "secure": True|False,
            "data": {
                "m": ... encrypted message ...,
                "s": ... message signature ...,
                "k": ... encrypted symmetric key ...
            }, # or if connection is insecure:
            "data": {
                "raw": "data"
            }
        }
        ```"""
        if self.rotate:
            self.rotate_aes()
        result = {
            "version": Protocol.VERSION,
            "secure": self.secure,
            "data": None
        }
        if self.secure:
            if is_json:
                message = json.dumps(message)
            message = _str_to_bytes(message)
            signature = Crypto.sign(message, self.priv)
            encrypted = Crypto.aes_encrypt(message, self.key, self.iv)
            symmetric_key = json.dumps({ "key": b64e(self.key), "iv": b64e(self.iv) })
            encrypted_symmetric_key = Crypto.encrypt(_str_to_bytes(symmetric_key), self.rpub)
            result["data"] = {
                "m": b64e(encrypted),
                "s": b64e(signature),
                "k": b64e(encrypted_symmetric_key)
            }
        else:
            result["data"] = message
        return json.dumps(result)

    def decrypt(self, data: str, ignore_invalid_signature: bool = False, return_raw: bool = False) -> str:
        """Takes an encrypted message (must be encrypted by an official Jarvis `Protocol.encrypt()` message)  
        Reverses the process done by `Protocol.encrypt()`  

        1. Convert JSON string to object
        2. Is message secure?
            * Yes:
                1. Decrypt the symmetric key using RSA
                2. Decrypt the message using AES
                3. Check the signature
            * No:
                1. Load the unencrypted message data
        3. Return the transmitted data
        """
        data = json.loads(data)
        if "version" not in data:
            logger.e("Unknown", "Unknown protocol, no version tag present, skipping message", "")
            return None
        if data["version"] != Protocol.VERSION:
            logger.e("Version", f"Version mismatch: local {Protocol.VERSION} vs. remote {data['version']}", "")
        secure = data["secure"]
        if data["version"] == 1:
            if secure:
                m = b64d(data["m"])
                s = b64d(data["s"])
                k = b64d(data["k"])
                symkey = json.loads(_bytes_to_str(Crypto.decrypt(k, _bytes_to_str(self.priv))))
                key = b64d(symkey["key"])
                iv = b64d(symkey["iv"])
                decrypted_message = Crypto.aes_decrypt(m, key, iv)
                sign_match = Crypto.verify(decrypted_message, s, self.rpub)
                if not sign_match:
                    if not ignore_invalid_signature:
                        raise Exception("Invalid Signature")
                if return_raw:
                    data["data"] = _bytes_to_str(decrypted_message)
                    return data
                else:
                    return _bytes_to_str(decrypted_message)
            else:
                return data if return_raw else json.dumps(data["data"])
        logger.e("Version", "Version mismatch: Failed to decrypt message", "")

    def rotate_aes(self):
        """Generate a new AES key and initialization vector.  
        Call this function as often as possible, changing AES keys does not break communication"""
        self.key, self.iv = Crypto.symmetric()

def b64e(bytes):
    """Base64 encode bytes"""
    return _bytes_to_str(base64.b64encode(bytes))

def b64d(bytes):
    """Base64 decode bytes"""
    return base64.b64decode(bytes)

def _bytes_to_str(byte_like_obj: bytes):
    return byte_like_obj.decode("utf-8")

def _str_to_bytes(string: str):
    return str.encode(string, "utf-8")
