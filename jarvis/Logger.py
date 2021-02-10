#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

from datetime import datetime
from jarvis import Database
import time
import json
import traceback

# MAX_LOGF_SIZE = 100 * 1024 * 1024		# 100MB
MAX_LOGF_SIZE = 20 * 1024 * 1024		# 20MB
MAX_FAST_LENGTH = 1000					# 1000 entries


class Logger:
    def __init__(self, referer):
        self.db = Database()
        self.referer = referer
        self.fast = False
        self.grouping = False
        self.to_cfsole = False
        self.fast_log_data = []

    def console_on(self):
        self.to_console = True

    def console_off(self):
        self.to_console = False

    def new_group(self, data: object):
        self.grouping = True
        self.fast_log_data.append({"meta": data, "data": []})

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

    def enable_fast(self):
        self.fast = True
        self.clear_fast()

    def disable_fast(self):
        self.fast = False
        self.clear_fast()

    def clear_fast(self):
        del self.fast_log_data
        self.fast_log_data = []

    def get_fast(self):
        return self.fast_log_data

    def wr(self, pre: str, tag: str, message: object):
        if self.fast:
            if len(self.fast_log_data) > MAX_FAST_LENGTH:
                self.clear_fast()

            msg_to_store = message  # should be an object
            if isinstance(message, str):
                try:
                    msg_to_store = json.loads(message)
                except Exception as e:
                    # print(e)
                    pass

            if self.grouping:
                # print(len(self.fast_log_data))
                self.fast_log_data[-1]["data"].append({
                    "severity": pre,
                    "tag": tag,
                    "message": msg_to_store
                })
            if not self.grouping:
                self.fast_log_data.append({
                    "severity": pre,
                    "tag": tag,
                    "message": msg_to_store
                })

        if self.to_console:
            print("{} - {} - {}/{}{} {}".format(str(datetime.now()), self.referer + (" " * (15-len(self.referer))), pre, tag, " " * (15-len(tag)), message))

            self.db.table("logs").insert({
                "timestamp": time.time(),
                "referer": self.referer,
                "importance": pre,
                "tag": tag,
                "message": message
            })
