#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

from typing import Callable
from jarvis import Logger
import paho.mqtt.client as mqtt
import random
import string
import traceback


class MQTT:
    """
    An easy-to-use MQTT wrapper for Jarvis applications
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 1883, client_id: str = None):
        """
        Initialize a MQTT instance with the following arguments:  
        * `host` specifies the hostname of the MQTT broker (default 127.0.0.1)  
        * `port` specifies the port of the MQTT broker (default 1883)  
        * `client_id` specifies a client id to identify the instance
        """
        self.host = host
        self.port = port

        if client_id is None:
            self.client_id = ''.join(random.choices(
                string.ascii_uppercase + string.digits, k=8))
        else:
            self.client_id = str(client_id)

        self.client = mqtt.Client(client_id=client_id)

        try:
            self.client.connect(self.host, self.port)
        except Exception:
            Logger.Logger.e1("mqtt", "refused",
                             "connection refused, mosquitto not installed", traceback.format_exc())
            exit(1)

        self.client.loop_start()

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
        return self.client.disconnect()