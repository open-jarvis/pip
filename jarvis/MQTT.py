#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

from typing import Callable
from jarvis import Logger
import paho.mqtt.client as pahomqtt
import random
import traceback


class MQTT:
    """
    An easy-to-use MQTT wrapper for Jarvis applications
    """


    def __init__(self, client_id: str = None, host: str = "127.0.0.1", port: int = 1883):
        """
        Initialize a MQTT instance with the following arguments:  
        * `host` specifies the hostname of the MQTT broker (default 127.0.0.1)  
        * `port` specifies the port of the MQTT broker (default 1883)  
        * `client_id` specifies a client id to identify the instance
        """
        self.host = host
        self.port = port

        self.client = pahomqtt.Client('jarvis|' + ''.join(random.choices("0123456abcdef", k=16)))

        try:
            self.client.connect(self.host, self.port)
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
        self.client.on_message = fn

    def publish(self, topic: str, payload: str):
        """
        Publish a MQTT message
        * `topic` specifies the topic (eg. application/lights/on)
        * `payload` describes the payload
        """
        return self.client.publish(topic, payload)

    def subscribe(self, topic: str):
        """
        Subscribe to a topic (`on_message` has to be called first)
        * `topic` to subscribe to
        """
        return self.client.subscribe(topic)

    def disconnect(self):
        """
        Disconnect from the broker cleanly.  
        Using disconnect() will not result in a will message being sent by the broker.
        """
        self.client.disconnect()
        return True
