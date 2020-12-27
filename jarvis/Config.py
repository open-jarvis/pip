#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import os, json

class Config:
	def __init__(self, user, filename="main.conf"):
		self.file = f"/home/{user}/.config/jarvis/{filename}"
		self.path = os.path.dirname(os.path.abspath(self.file))

	def exists(self):
		return os.path.exists(self.file)

	def create(self):
		if not os.path.exists(self.path):
			os.makedirs(self.path)
			with open(self.file, "w") as f:
				f.write(json.dumps({}))

	def create_if_not_exists(self):
		if not self.exists():
			self.create()

	def get(self):
		cnf = {}
		try:
			if not self.exists():
				self.create()
			with open(self.file, "r") as f:
				cnf = json.loads(f.read())
		except Exception as e:
			pass
		return cnf

	def set_key(self, key, value):
		cnf = self.get()
		cnf[key] = value
		with open(self.file, "w") as f:
			f.write(json.dumps(cnf))

	def get_key(self, key, or_else):
		cnf = self.get()
		if key in cnf:
			return cnf[key]
		else:
			return or_else
