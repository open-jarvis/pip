#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

from urllib import request, parse
from multiprocessing import Process
import json, time


class Jarvis:
	def __init__(self, host, token, port=2021):
		self.host = host
		self.token = token
		self.port = port
		self.connected = False


	
	def connect(self, reconnect_on_error=True):
		resp = self._post("register-device?name={}&token={}&type={}&native={}".format("Jarvis Headset", self.token, "headset", "true"), {})
		resp = json.loads(resp)
		if resp["success"]:
			self.connected = True
			self._start_hello_thread()
			return True
		else:
			self.connected = False
			if reconnect_on_error:
				return self.reconnect()
			return False
	def reconnect(self):
		resp = self._post(	"am-i-registered?token={}".format(self.token), {})
		resp = json.loads(resp)
		if resp["success"]:
			self.connected = True
			self._start_hello_thread()
			return True
		else:
			self.connected = False
			return False



	def set_property(self, key, value):
		pass



	def _start_hello_thread(self):
		self.hello_process = Process(target=Jarvis._hello_thread, args=(self.host, self.token, self.port))
		self.hello_process.start()
	def _stop_hello_thread(self):
		self.hello_process.terminate()

	def _post(self, endpoint, post_data):
		url = "http://{}:{}/{}".format(self.host, self.port, endpoint) 
		data = str(json.dumps(post_data)).encode('utf-8')
		req = request.Request(url, data=data)
		return request.urlopen(req).read()

	@staticmethod
	def _hello_thread(h,t,p):
		while True:
			req = request.Request("http://{}:{}/{}".format(h,p,"hello?token="+t))
			req.read()
			time.sleep(5)