"""
Copyright (c) 2021 Philipp Scheer
"""


import json
from jarvis.MQTT import MQTT
from jarvis.Crypto import Crypto
from jarvis.Logger import Logger
from jarvis.Protocol import Protocol
from jarvis.API import API


logger = Logger("Client")


class Client:
    """A client communication handler.  
    Applications should use this class to communicate securely with the server"""

    def __init__(self, client_id: str, private_key: str, public_key: str, server_public_key: str = None) -> None:
        """Create a new instance using a local `private_key` and `public_key`. 
        You need to store these files on your device and make sure they're safe.
        If you do not specify a `server_public_key`, an attempt to retrieve it from the server will be made  
        Use the [`Crypto`](Crypto) class to generate keys:
        ```python
        priv, pub = Crypto.keygen(4096)
        ```
        You can also use 2048 bitlength but to be on the safe side 4096 is recommended  
        Use 2048 bits only if your device CPU is weak or you don't really care about security
        """
        self.id = client_id
        self.priv = private_key
        self.pub = public_key
        self.rpub = None
        self.rpub = self._endpoint(f"jarvis/server/get/public-key", {})["result"]
        # when placing the rpub getter before the pub setter, the signature mismatch happens on the server, which is harder to fix but more secure
        self._allow_insecure = False
        self.pub_accepted = self._endpoint(f"jarvis/client/{self.id}/set/public-key", {"public-key": self.pub})["success"]
        # TODO: getting rsa.pkcs1.DecryptionError: Decryption failed
        # we have the rpub, priv and pub
        # maybe the server is encrypting using a wrong public key...
        if self.rpub is None:
            self.get_identity()

    def request(self, topic: str, message: object, wait_for_response: bool = True):
        """Request a server ressource  
        Specify the `topic` and `message` MQTT parameters.
        `topic` must be a string that specifies a server ressource and `message` must be an object (NOT a JSON string!)  
        If `wait_for_response` is set to `False`, just send out the request and don't wait for a response  
        
        This function might raise an exception if the remote public key is unknown and cannot be retrieved.  
        (The ready check is skipped, if `allow_insecure()` has been called)"""
        if self.rpub is None and not self._allow_insecure:
            logger.e("Security", "No remote public key available. Won't send unencrypted message", "")
            return None
        if not self.pub_accepted:
            logger.e("Security", "Remote server did not accept local public key. Won't send unencrypted message", "")
            return None
        proto = Protocol(self.priv, self.pub, self.rpub, auto_rotate=True)
        message = json.loads(proto.encrypt(message, is_json=True))
        return json.loads(
                    proto.decrypt(
                        MQTT.onetime(self.id, self.priv, self.pub, topic, message, remote_public_key=self.rpub, timeout=15 if wait_for_response else 0, send_raw=False, qos=0), 
                        ignore_invalid_signature=False, 
                        return_raw=False))

    def _endpoint(self, topic: str, message: object, wait_for_response: bool = True, qos=0):
        return MQTT.onetime(self.id, self.priv, self.pub, topic, message, self.rpub, timeout=15 if wait_for_response else 0, qos=qos)
