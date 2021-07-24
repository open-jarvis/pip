"""
Copyright (c) 2021 Philipp Scheer
"""


from jarvis.MQTT import MQTT


class Connection:
    """A device communication handler.  
    Applications and devices should use this class to communicate securely with the server"""

    def __init__(self, device_id: str) -> None:
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
        self.id = device_id

    def request(self, topic: str, message: object, wait_for_response: bool = True, qos=0):
        """Request an MQTT API endpoint"""
        return MQTT.endpoint(self.id, topic, message, timeout=15 if wait_for_response else 0, qos=qos)
