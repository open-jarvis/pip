#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import time
import traceback
from datetime import datetime
from jarvis import Database

MAX_LOGF_SIZE = 20 * 1024 * 1024		# 20MB


class Logger:
    def __init__(self, referer):
        self.referer = referer
        self.to_console = True

    def console_on(self):
        self.to_console = True

    def console_off(self):
        self.to_console = False

    def new_group(self, data: object):
        self.grouping = True

    def i(self, tag: str, message: str):
        self.wr("I", tag, message)

    def e(self, tag: str, message: str):
        self.wr("E", tag, message)

    def w(self, tag: str, message: str):
        self.wr("W", tag, message)

    def s(self, tag: str, message: str):
        self.wr("S", tag, message)

    def c(self, tag: str, message: str):
        self.wr("C", tag, message)

    def exception(self, tag: str, exception: Exception = None):
        self.e(tag, traceback.format_exc())

    def wr(self, pre: str, tag: str, message: object):
        if self.to_console:
            print("{} - {} - {}/{}{} {}".format(str(datetime.now()), self.referer +
                                                (" " * (15-len(self.referer))), pre, tag, " " * (15-len(tag)), message))

            Database.Database().table("logs").insert({
                "timestamp": time.time(),
                "referer": self.referer,
                "importance": pre,
                "tag": tag,
                "message": message
            })
