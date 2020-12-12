#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import paho.mqtt.client as mqtt

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
		
		log("mqtt", "creating client '{}'".format(self.client_id))
		self.client = mqtt.Client(client_id=client_id)
		log("mqtt", "connecting to '{}:{}'".format(str(self.host), str(self.port)))
		self.client.connect(self.host, self.port)
		log("mqtt", "starting event loop")
		self.client.loop_start()

	def on_connect(self, fn):
		log("mqtt", "adding 'on_connect' callback")
		self.client.on_connect = fn

	def on_message(self, fn):
		log("mqtt", "adding 'on_message' callback")
		self.client.on_message = fn

	def publish(self, topic, payload, disable_log=False):
		if not disable_log:
			log("mqtt", "publishing message: {}:{} -> {} -> '{}'".format(str(self.host), str(self.port), str(topic), str(payload)))
		return self.client.publish(topic, payload)

	def subscribe(self, topic):
		log("mqtt", "subscribing to {}:{} {}".format(str(self.host), str(self.port), str(topic)))
		return self.client.subscribe(topic)

