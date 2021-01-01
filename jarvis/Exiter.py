#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import signal

class Exiter:
	def __init__(self, on_exit_fn, args=None):
		self.on_exit_fn = on_exit_fn
		self.args = args
		signal.signal(signal.SIGINT, self.exit_fn)
		signal.signal(signal.SIGTERM, self.exit_fn)

	def exit_fn(self, signum, frame):
		self.on_exit_fn() if self.args is None else self.on_exit_fn(*self.args)
