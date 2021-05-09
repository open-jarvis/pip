"""
Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.

The Jarvis class handles MQTT application access and is part of the <a href="https://pypi.org/project/open-jarvis">open-jarvis pip package</a>
"""

import json
import time
import random
import string
from jarvis import MQTT

APPLICATION_TOKEN_LENGTH = 32
"""Length of an application token"""
ONE_TIME_CHANNEL_LENGTH = 64
"""Length of the one-time MQTT reply channel"""


class Jarvis:
    """
    Jarvis provides an MQTT API wrapper for the <a href="https://github.com/open-jarvis/server">Jarvis server</a>
    """

    _responses = {}

    def __init__(self, host: str = "127.0.0.1", port: int = 1883, client_id: str = "mqtt_jarvis") -> None:
        """
        Create a Jarvis API instance  
        * `host` specifies the ip or hostname of the MQTT broker (default 127.0.0.1)  
        * `port` specifies the port number of the MQTT broker (default 1883)  
        * `client_id` specifies the MQTT client identifier
        """
        self.host = host
        self.port = port
        self.mqtt = MQTT.MQTT(host, port, client_id=client_id)
        self.mqtt.on_message(Jarvis._on_msg)
        self.mqtt.subscribe("#")
        self.faster = False
        self.token = None
        """The application token"""

    # TODO: how to verify the application?
    # TODO: no protection yet
    def register(self, name: str):
        """
        Registers an application with the Jarvis backend  
        * `name` specifies the application name  
        A random token will be generated and returned
        """
        self.token = "app:" + ''.join(random.choice(string.ascii_lowercase + string.digits)
                                      for _ in range(APPLICATION_TOKEN_LENGTH))
        return json.loads(self._send_and_receive("jarvis/api/register-device", {"name": name, "type": "app"}))

    def get_devices(self):
        """
        Returns a list of all registered devices and applications  
        """
        return json.loads(self._send_and_receive("jarvis/api/get-devices"))

    def get_property(self, property: str, target_token: str = None, or_else: any = None):
        """
        Return properties of target devices  
        * `property` tells the backend which property to search for  
        * `target_token` filters properties by token, can be None to return `property` from all devices
        """
        return json.loads(self._send_and_receive("jarvis/api/get-property", {"property": property,
                                                                             "target-token": target_token} if target_token is not None else {"property": property}))

    def set_property(self, property: str, value: object):
        """
        Set the property of the current application  
        * `property` to set  
        * `value` to set `property` to
        """
        return json.loads(self._send_and_receive("jarvis/api/set-property", {"property": property, "value": value}))

    def decision_ask(self, typ: str, title: str, infos: str, options: list):
        """
        Create a decision request  
        * `typ` specifies the type of the decision request (see <a href="https://open-jarvis.github.io/#id-call">the official docs</a> for more)  
        * `title` specifies a title or a general information  
        * `infos` sets a more detailled description string  
        * `options` is an array of objects with the following structure: ```[ {"text": "Accept call", "color": "red" | "#ff3f3f", "icon": "base64" | "material"}, ... ]```
        """
        return json.loads(self._send_and_receive("jarvis/api/decision/ask", {"type": typ, "title": title, "infos": infos, "options": options}))

    def decision_answer(self, id: str, option_index: int, description: str = None):
        """
        Answer a decision request  
        * `id` is the decision id to answer  
        * `option_index` is the index in the options array  
        * `description` is a short description why this decision was answered
        """
        return json.loads(self._send_and_receive("jarvis/api/decision/answer", {"id": id, "option": option_index} if description is None else {"id": id, "option": option_index, "description": description}))

    def decision_scan(self, target_token: str = None, typ: str = None):
        """
        Scan for decision requests  
        * `target_token` (optional) is a token of the target device or application to scan  
        * `typ` (optional) is a type to scan for (see <a href="https://open-jarvis.github.io/#id-call">the official docs</a> for more)
        """
        obj = {}
        if target_token is not None:
            obj["target-token"] = target_token
        if typ is not None:
            obj["type"] = typ
        return json.loads(self._send_and_receive("jarvis/api/decision/scan", obj))

    def decision_delete(self, id: str):
        """
        Delete an decision request
        * `id` specifies the decision id to delete
        """
        return json.loads(self._send_and_receive("jarvis/api/decision/delete", {"id": id}))

    def _send_and_receive(self, topic: str, message: object = {}, timeout: int = 2):
        if self.token is None:
            raise AttributeError("self.token is None!")
        message["token"] = self.token
        if self.faster:
            self.mqtt.publish(topic, json.dumps(message))
            return "{}"
        else:
            return Jarvis.api(topic, message, timeout)

    @staticmethod
    def api(topic: str, message: object, timeout: int = 2):
        try:
            otc = "jarvis/tmp/" + \
                ''.join(random.choice("0123456789abcdef")
                        for _ in range(ONE_TIME_CHANNEL_LENGTH))
            message["reply-to"] = otc
            mqtt = MQTT.MQTT(client_id="one-time-" + str(time.time()))
            mqtt.on_message(Jarvis._on_msg)
            mqtt.subscribe("#")
            mqtt.publish(topic, json.dumps(message))
            start = time.time()
            while otc not in Jarvis._responses:
                time.sleep(0.1)
                if start + timeout < time.time():
                    Jarvis._responses[otc] = False
            response = Jarvis._responses[otc]
            del Jarvis._responses[otc]
            mqtt.disconnect()
            del mqtt
            return response
        except Exception:
            return '{"success":false}'


    @staticmethod
    def _on_msg(client: object, userdata: object, message: object):
        topic = message.topic
        data = message.payload.decode()
        if topic.startswith("jarvis/tmp/"):
            Jarvis._responses[topic] = data
