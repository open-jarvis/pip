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
        self.rpub = self.request(f"jarvis/server/get/public-key", {})["result"]
        # when placing the rpub getter before the pub setter, the signature mismatch happens on the server, which is harder to fix but more secure
        self.pub_accepted = self.send_identity()
        if not self.pub_accepted:
            raise Exception("Server did not acknowledge public key")
        # How the protocol works:
        # P ... plaintext traffic, E ... encrypted traffic
        # P < jarvis/server/get/public-key     : reply-to
        # P > reply-to                         : public key
        # E < jarvis/client/id/set/public-key  : public-key, reply-to
        # E > reply-to                         : ok ? True | False

    def request(self, topic: str, message: object, wait_for_response: bool = True, qos=0):
        return MQTT.onetime(self.id, self.priv, self.pub, topic, message, self.rpub, timeout=15 if wait_for_response else 0, qos=qos)

    def send_identity(self, public_key: str = None):
        if public_key is None:
            public_key = self.pub
        accepted = False
        try:
            accepted = self.request(f"jarvis/client/{self.id}/set/public-key", {"public-key": public_key}).get("success", False)
        finally:
            return accepted

    def update_keys(self, new_private_key: str, new_public_key: str):
        accepted = self.send_identity(new_public_key)
        if accepted:
            self.priv, self.pub = new_private_key, new_public_key
        return accepted
