#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import paho.mqtt.client as mqtt
import random, string

# MQTT(host=127.0.0.1, port=1883, client_id=[random])
# 	.on_connect(callback[client, userdata, flags, rc])
# 	.on_message(callback[client, userdata, message])
# 	.publish(topic, payload)
# 	.subscribe(topic)
class MQTT():
	def __init__(self, host="127.0.0.1", port=1883, client_id=None):
		self.host = host
		self.port = port

		if client_id is None:
			self.client_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
		else:
			self.client_id = str(client_id)
		
		self.client = mqtt.Client(client_id=client_id)
		self.client.connect(self.host, self.port)
		self.client.loop_start()

	def on_connect(self, fn):
		self.client.on_connect = fn

	def on_message(self, fn):
		self.client.on_message = fn

	def publish(self, topic, payload, disable_log=False):
		return self.client.publish(topic, payload)

	def subscribe(self, topic):
		return self.client.subscribe(topic)

