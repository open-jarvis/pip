"""
Copyright (c) 2021 Philipp Scheer
"""


import time
import json
from typing import Callable
from jarvis import Logger
from jarvis.Protocol import Protocol
from paho.mqtt.client import Client
from paho.mqtt.matcher import MQTTMatcher
import random
import traceback


ONE_TIME_CHANNEL_LENGTH = 64
"""Length in characters (bytes) of the one time channel"""

TMP_PREFIX = "jrvs/tmp/"
"""The temporary channel prefix"""

ENCRYPTED_CHANNEL = "jarvis/encrypted"
"""The encrypted channel to exchange traffic  
(Also unencrypted traffic flows over this channel)"""


class MQTT:
    """
    An easy-to-use MQTT wrapper for Jarvis applications
    """

    QOS_LOW = 0
    QOS_MEDIUM = 1
    QOS_HIGH = 2

    _responses = {}
    """A storage for all received reponses generated by `onetime()`"""

    def __init__(self, client_id: str, private_key: str = None, public_key: str = None, remote_public_key: str = None, userdata: str = "anonymous", host: str = "127.0.0.1", port: int = 1883):
        """
        Initialize a MQTT instance with the following arguments:  
        * `host` specifies the hostname of the MQTT broker (default 127.0.0.1)  
        * `port` specifies the port of the MQTT broker (default 1883)  
        * The `userdata` parameter will be passed to callbacks 
        """
        self.host  = host
        self.port  = port
        self.priv  = private_key
        self.pub   = public_key
        self.rpub  = remote_public_key
        self.cid   = client_id
        self.cb    = None
        self.subscriptions = []
        self.proto = Protocol(self.priv, self.pub, self.rpub, auto_rotate=True)

        self.client = Client('jarvis|' + ''.join(random.choices("0123456abcdef", k=16)), userdata=userdata)

        try:
            self.client.connect(self.host, self.port)
            self.client.on_message = self._mqtt_cb
            self.client.subscribe(ENCRYPTED_CHANNEL)
        except Exception:
            print(traceback.format_exc())
            Logger.Logger.e1("MQTT", "Refused", "Connection refused, mosquitto not installed or not running", traceback.format_exc())

    def on_connect(self, fn: Callable):
        """
        A callback function to handle a connection event  
        * `fn` is a callable (usually a function) with the following arguments: [client, userdata, flags, rc]
        """
        self.client.on_connect = fn

    def on_message(self, fn: Callable):
        """
        A callback function to handle a message receive event  
        * `fn` is a callable (usually a function) with the following arguments: [client, userdata, message]
        """
        self.client.loop_start()
        self.cb = fn

    def publish(self, topic: str, payload: str, qos: int = 0):
        """
        Publish a MQTT message
        * `topic` specifies the topic (eg. application/lights/on)
        * `payload` describes the payload
        """
        data = {
            "t": topic,
            "p": payload,
            "c": self.cid
        }
        encrypted_topic = ENCRYPTED_CHANNEL
        encrypted_payload = self.proto.encrypt(data, is_json=True)
        return self.client.publish(encrypted_topic, encrypted_payload, qos=qos)

    def subscribe(self, topic: str):
        """
        Subscribe to a topic (`on_message` has to be called first)
        * `topic` to subscribe to  
        You can subscribe to multiple channels by calling this function more often.  
        You can also use the '+' and '#' specifiers
        """
        return self.subscriptions.append(topic)

    def disconnect(self):
        """
        Disconnect from the broker cleanly.  
        Using disconnect() will not result in a will message being sent by the broker.
        """
        self.client.disconnect()
        return True

    def update_public_key(self, public_key: str):
        """Update the remote public key and generate a new Protocol object"""
        self.rpub = public_key
        self.proto = Protocol(self.priv, self.pub, self.rpub, auto_rotate=True)

    def _mqtt_cb(self, client, userdata, message):
        payload   = message.payload.decode()
        payload   = json.loads(self.proto.decrypt(payload, ignore_invalid_signature=False, return_raw=False))
        topic     = payload["t"]
        payload   = payload["p"]
        client_id = payload["c"]
        matches   = False
        for sub in self.subscriptions:
            if MQTT.match(sub, topic):
                matches = True
        if matches and self.cb is not None:
            self.cb(topic, payload, client_id)

    @staticmethod
    def onetime(topic: str, message: object, userdata: str = "anonymous", timeout: int = 2, send_raw: bool = False, qos: int = 0) -> str:
        """Send a onetime message and wait for a result.  
        The client should respond to the generated 'reply-to' channel  
        If `timeout` is 0, return immediately and don't wait for a response. Message does not include a `reply-to` channel then  
        If `send_raw` is `True`, send the raw `message` string (must convert to string before!)"""
        try:
            if timeout != 0:
                otc = TMP_PREFIX + ''.join(random.choice("0123456789abcdef") for _ in range(ONE_TIME_CHANNEL_LENGTH))
                message["reply-to"] = otc
            mqtt = MQTT(userdata=userdata)
            mqtt.on_message(MQTT._on_msg)
            mqtt.subscribe("#")
            mqtt.publish(topic, message if send_raw else json.dumps(message))
            if timeout == 0: # return if timeout = 0
                mqtt.disconnect()
                return
            start = time.time()
            while otc not in MQTT._responses:
                time.sleep(0.1)
                if start + timeout < time.time():
                    MQTT._responses[otc] = False
            response = MQTT._responses[otc]
            del MQTT._responses[otc]
            mqtt.disconnect()
            del mqtt
            return response
        except Exception as e:
            raise e

    @staticmethod
    def _on_msg(client: object, userdata: object, message: object):
        topic = message.topic
        data = message.payload.decode()
        if topic.startswith(TMP_PREFIX):
            MQTT._responses[topic] = data

    @staticmethod
    def match(subscription: str, topic: str) -> bool:
        """Check whether a topic matches a subscription.  
        For example:  
        foo/bar would match the subscription foo/# or +/bar  
        non/matching would not match the subscription non/+/+
        """
        matcher = MQTTMatcher()
        matcher[subscription] = True
        try:
            next(matcher.iter_match(topic))
            return True
        except StopIteration:
            return False
