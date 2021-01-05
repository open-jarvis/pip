#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import signal

class Exiter:
	running = True
	exit_fn_list = []

	def __init__(self, on_exit_fn, args=None):
			Exiter.exit_fn_list.append({"fn":on_exit_fn, "args":args})

	@staticmethod
	def exit_fn(signum, frame):
			Exiter.running = False
			for fn in Exiter.exit_fn_list:
					fn["fn"]() if fn["args"] is None else fn["fn"](*fn["args"])

signal.signal(signal.SIGINT, Exiter.exit_fn)
signal.signal(signal.SIGTERM, Exiter.exit_fn)