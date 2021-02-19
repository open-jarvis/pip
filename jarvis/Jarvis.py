#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import json
import time
import random
import string
from jarvis import MQTT

APPLICATION_TOKEN_LENGTH = 32
ONE_TIME_CHANNEL_LENGTH = 64


# MQTT interface for applications
class Jarvis:
    _responses = {}

    def __init__(self, host: str = "127.0.0.1", port: int = 1883, client_id: str = "mqtt_jarvis") -> None:
        self.host = host
        self.port = port
        self.mqtt = MQTT.MQTT(host, port, client_id=client_id)
        self.mqtt.on_message(Jarvis._on_msg)
        self.mqtt.subscribe("#")
        self.token = None

    # TODO: how to verify the application?
    # TODO: no protection yet
    def register(self, name: str):
        self.token = "app:" + ''.join(random.choice(string.ascii_lowercase + string.digits)
                                      for _ in range(APPLICATION_TOKEN_LENGTH))
        return json.loads(self._send_and_receive("jarvis/api/register-device", {"name": name}))

    def get_devices(self):
        return json.loads(self._send_and_receive("jarvis/api/get-devices"))

    def get_property(self, key: str, target_token: str = None):
        return json.loads(self._send_and_receive("jarvis/api/get-property", {"key": key, "target-token": target_token} if target_token is None else {"key": key}))

    def set_property(self, target_token: str, key: str, value: object):
        return json.loads(self._send_and_receive("jarvis/api/set-property", {"target-token": target_token, "key": key, "value": value}))

    def instant_ask(self, typ: str, name: str, infos: str, options: list):
        return json.loads(self._send_and_receive("jarvis/api/id/ask", {"type": typ, "name": name, "infos": infos, "options": options}))

    def instant_answer(self, target_token: str, typ: str, option_index: int, description: str):
        return json.loads(self._send_and_receive("jarvis/api/id/answer", {"target-token": target_token, "type": typ, "option-index": option_index, "description": description}))

    def instant_scan(self, target_token: str = None, typ: str = None):
        obj = {}
        if target_token is not None:
            obj["target-token"] = target_token
        if typ is not None:
            obj["type"] = typ
        return json.loads(self._send_and_receive("jarvis/api/id/scan", obj))

    def instant_delete(self, target_token: str, typ: str):
        return json.loads(self._send_and_receive("jarvis/api/id/delete", {"target-token": target_token, "type": typ}))

    def _send_and_receive(self, topic: str, message: object = {}):
        if self.token is None:
            raise AttributeError("self.token is None!")
        one_time_channel = "jarvis/reply/" + \
            ''.join(random.choice("0123456789abcdef")
                    for _ in range(ONE_TIME_CHANNEL_LENGTH))
        message["token"] = self.token
        message["reply-to"] = one_time_channel
        self.mqtt.publish(topic, json.dumps(message))
        while one_time_channel not in Jarvis._responses:
            time.sleep(0.1)
        response = Jarvis._responses[one_time_channel]
        del Jarvis._responses[one_time_channel]
        return response

    @staticmethod
    def _on_msg(client: object, userdata: object, message: object):
        topic = message.topic
        data = message.payload.decode()
        if topic.startswith("jarvis/reply/"):
            Jarvis._responses[topic] = data
