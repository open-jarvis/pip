#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import time
import traceback
from datetime import datetime
from jarvis import Database


class Logger:
    """
    A Logger class that logs to console and to Database
    """

    _pause = False
    """Pause logging"""

    def __init__(self, referrer):
        """
        Initialize the logger
        * `referrer` specifies the code piece that runs the Logger class.  
            This could be the name of the Python file or another descriptive name
        """
        self.referrer = referrer
        self.to_console = True

    def console_on(self):
        """Turn console logging on"""
        self.to_console = True

    @staticmethod
    def pause():
        """Pause logging"""
        Logger._pause = True
    
    @staticmethod
    def resume():
        """Resume logging"""
        Logger._pause = False

    def console_off(self):
        """Turn console logging off"""
        self.to_console = False

    def i(self, tag: str, message: str, to_db: bool = True):
        """Log an `info` message"""
        Logger.log(self.referrer, "I", tag, message, to_console=self.to_console, database_entry=to_db)

    def e(self, tag: str, message: str, exception_str: str, to_db: bool = True):
        """Log an `error` message"""
        Logger.log(self.referrer, "E", tag, message, to_console=self.to_console, exception_str=exception_str, database_entry=to_db)

    def w(self, tag: str, message: str, to_db: bool = True):
        """Log a `warning` message"""
        Logger.log(self.referrer, "W", tag, message, to_console=self.to_console, database_entry=to_db)

    def s(self, tag: str, message: str, to_db: bool = True):
        """Log a `success` message"""
        Logger.log(self.referrer, "S", tag, message, to_console=self.to_console, database_entry=to_db)

    def c(self, tag: str, message: str, to_db: bool = True):
        """Log a `critical` message"""
        Logger.log(self.referrer, "C", tag, message, to_console=self.to_console, database_entry=to_db)

    @staticmethod
    def log(referrer: str, pre: str, tag: str, message: object, exception_str: str = None, to_console: bool = True, database_entry: bool = True):
        """
        This function creates the log entry  
        It's used be the `Logger` class but also from outside, if all arguments are provided
        * `referrer` specifies the referring Python script or another descriptive string
        * `pre` is either I, W, E, S or C which stands for info, warning, error, success or critical
        * `tag` is a small string that describes the message
        * `message` is the actual message
        * `exception_str` contains the exception traceback if any
        * `to_console` sets if the message should be printed to console
        * `database_entry` specifies if a database entry should be made  
            If the database is down, set this to False
        """
        if Logger._pause:
            return

        if to_console:
            print("{} - {}/{} - {}".format(str(datetime.now()), pre, referrer +
                                           (" " * (12-len(referrer))), message))

        if database_entry:
            obj = {
                "timestamp": time.time(),
                "referrer": referrer,
                "importance": pre,
                "tag": tag,
                "message": message
            }
            if exception_str is not None:
                obj["exception"] = exception_str

            try:
                Database.Database(exit_on_fail=False).table("logs").insert(obj)
            except Database.Database.Exception:
                Logger.e1("Logger", "DB", "Failed to insert log data, database not running", traceback.format_exc(), database_entry=False)

    @staticmethod
    def i1(referrer: str, tag: str, message: object, database_entry: bool = True):
        """Create a one-time info log message"""
        Logger.log(referrer, "I", tag, message, to_console=True, database_entry=database_entry)

    @staticmethod
    def e1(referrer: str, tag: str, message: object, exception_str: str, database_entry: bool = True):
        """Create a one-time error log message"""
        Logger.log(referrer, "E", tag, message, exception_str=exception_str, to_console=True, database_entry=database_entry)

    @staticmethod
    def w1(referrer: str, tag: str, message: object, database_entry: bool = True):
        """Create a one-time warning log message"""
        Logger.log(referrer, "W", tag, message, to_console=True, database_entry=database_entry)

    @staticmethod
    def s1(referrer: str, tag: str, message: object, database_entry: bool = True):
        """Create a one-time success log message"""
        Logger.log(referrer, "S", tag, message, to_console=True, database_entry=database_entry)

    @staticmethod
    def c1(referrer: str, tag: str, message: object, database_entry: bool = True):
        """Create a one-time critical log message"""
        Logger.log(referrer, "C", tag, message, to_console=True, database_entry=database_entry)
