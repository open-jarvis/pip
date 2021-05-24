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
        self.rpub = server_public_key
        self._allow_insecure = False
        if self.rpub is None:
            self.get_identity()

        @API.route(f"jarvis/client/{self.id}/get/public-key")
        def getpubkey(d):
            return self.pub

    def request(self, topic: str, message: object, wait_for_response: bool = True):
        """Request a server ressource  
        Specify the `topic` and `message` MQTT parameters.
        `topic` must be a string that specifies a server ressource and `message` must be an object (NOT a JSON string!)  
        If `wait_for_response` is set to `False`, just send out the request and don't wait for a response  
        
        This function might raise an exception if the remote public key is unknown and cannot be retrieved.  
        (The ready check is skipped, if `allow_insecure()` has been called)"""
        proto = Protocol(self.priv, self.pub, self.rpub, auto_rotate=True)
        message = json.loads(proto.encrypt(message, is_json=True))
        return json.loads(proto.decrypt(MQTT.onetime(topic, message, timeout=15 if wait_for_response else 0, send_raw=False, qos=0), ignore_invalid_signature=False, return_raw=False))
        
    def ready(self, _ret: bool = False):
        """Check if this client instance is ready to send encrypted data to the server"""
        if self.rpub in (None, False):
            logger.w("Identity", "Public key of server not known! Won't send unencrypted message!", "")
            self.get_identity()
            if not _ret:
                self.ready(_ret=True)
            raise Exception("Public key of server not known! Won't send unencrypted message!")

    def get_identity(self):
        """Try to load the public key from the server.  
        If this is not possible, set the public key to false.  
        Unencrypted traffic is not allowed per default"""
        logger.i("Identity", "Trying to get server public key")
        response = self.request("jarvis/server/get/public-key", {}, wait_for_response=True)
        if response["success"]:
            self.rpub = response["response"]

    def allow_insecure(self):
        """Allow insecure traffic.  
        **Warning:** Only turn on this feature if you know what you're doing AND you know who the server is AND you know that the server is up  
        The use of this feature is discouraged!"""
        logger.w("Insecure", "Insecure traffic has been turned on! The use of this function is discouraged!")
        self._allow_insecure = True