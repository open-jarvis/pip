#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import time
import traceback
from datetime import datetime
# from jarvis import Database


class Logger:
    def __init__(self, referer):
        self.referer = referer
        self.to_console = True

    def console_on(self):
        self.to_console = True

    def console_off(self):
        self.to_console = False

    # def i(self, tag: str, message: str):
    #     Logger.log(self.referer, "I", tag, message, self.to_console)

    # def e(self, tag: str, message: str):
    #     Logger.log(self.referer, "E", tag, message, self.to_console)

    # def w(self, tag: str, message: str):
    #     Logger.log(self.referer, "W", tag, message, self.to_console)

    # def s(self, tag: str, message: str):
    #     Logger.log(self.referer, "S", tag, message, self.to_console)

    # def c(self, tag: str, message: str):
    #     Logger.log(self.referer, "C", tag, message, self.to_console)

    def exception(self, tag: str, exception: Exception = None):
        self.e(tag, traceback.format_exc())

    # @staticmethod
    # def log(referer: str, pre: str, tag: str, message: object, to_console: bool = True):
    #     if to_console:
    #         print("{} - {}/{} - {}".format(str(datetime.now()), pre, referer +
    #                                        (" " * (12-len(referer))), message))

    #         Database.Database().table("logs").insert({
    #             "timestamp": time.time(),
    #             "referer": referer,
    #             "importance": pre,
    #             "tag": tag,
    #             "message": message
    #         })

    # @staticmethod
    # def i1(referer: str, tag: str, message: object):
    #     Logger.log(referer, "I", tag, message, True)

    # @staticmethod
    # def e1(referer: str, tag: str, message: object):
    #     Logger.log(referer, "E", tag, message, True)

    # @staticmethod
    # def w1(referer: str, tag: str, message: object):
    #     Logger.log(referer, "W", tag, message, True)

    # @staticmethod
    # def s1(referer: str, tag: str, message: object):
    #     Logger.log(referer, "S", tag, message, True)

    # @staticmethod
    # def c1(referer: str, tag: str, message: object):
    #     Logger.log(referer, "C", tag, message, True)
