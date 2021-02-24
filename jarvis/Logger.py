#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import time
import traceback
from datetime import datetime
from jarvis import Database


class Logger:
    def __init__(self, referer):
        self.referer = referer
        self.to_console = True

    def console_on(self):
        self.to_console = True

    def console_off(self):
        self.to_console = False

    def i(self, tag: str, message: str):
        Logger.log(self.referer, "I", tag, message, to_console=self.to_console)

    def e(self, tag: str, message: str, exception_str: str):
        Logger.log(self.referer, "E", tag, message,
                   to_console=self.to_console, exception_str=exception_str)

    def w(self, tag: str, message: str):
        Logger.log(self.referer, "W", tag, message, to_console=self.to_console)

    def s(self, tag: str, message: str):
        Logger.log(self.referer, "S", tag, message, to_console=self.to_console)

    def c(self, tag: str, message: str):
        Logger.log(self.referer, "C", tag, message, to_console=self.to_console)

    @staticmethod
    def log(referer: str, pre: str, tag: str, message: object, exception_str: str = None, to_console: bool = True, database_entry: bool = True):
        if to_console:
            print("{} - {}/{} - {}".format(str(datetime.now()), pre, referer +
                                           (" " * (12-len(referer))), message))

        if database_entry:
            obj = {
                "timestamp": time.time(),
                "referer": referer,
                "importance": pre,
                "tag": tag,
                "message": message
            }
            if exception_str is not None:
                obj["exception"] = exception_str

            try:
                Database.Database().table("logs").insert(obj)
            except Database.Exception:
                Logger.e1("logger", "db-error", "failed to insert log data, database not running",
                          traceback.format_exc(), to_console=True, database_entry=False)
                exit(1)

    @staticmethod
    def i1(referer: str, tag: str, message: object, database_entry: bool = True):
        Logger.log(referer, "I", tag, message, to_console=True,
                   database_entry=database_entry)

    @staticmethod
    def e1(referer: str, tag: str, message: object, exception_str: str, database_entry: bool = True):
        Logger.log(referer, "E", tag, message, exception_str=exception_str,
                   to_console=True, database_entry=database_entry)

    @staticmethod
    def w1(referer: str, tag: str, message: object, database_entry: bool = True):
        Logger.log(referer, "W", tag, message, to_console=True,
                   database_entry=database_entry)

    @staticmethod
    def s1(referer: str, tag: str, message: object, database_entry: bool = True):
        Logger.log(referer, "S", tag, message, to_console=True,
                   database_entry=database_entry)

    @staticmethod
    def c1(referer: str, tag: str, message: object, database_entry: bool = True):
        Logger.log(referer, "C", tag, message, to_console=True,
                   database_entry=database_entry)
