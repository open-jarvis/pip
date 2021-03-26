#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#


from jarvis import Database, Logger
import traceback


class Config:
    """
    A config class to store and load configuration information from the database
    """

    def __init__(self) -> None:
        """
        Create an instance of the Config class.
        """
        self.db = Database.Database()

    def set(self, key: str, value: object) -> bool:
        """
        Set a configuration key to a given value.  
        sets `key` = `value`
        """
        try:
            if self.db.table("config").filter({"key": key}).found:
                self.db.table("config").filter({"key": key}).update({
                    "value": value
                })
            else:
                self.db.table("config").insert({
                    "key": key,
                    "value": value
                })
            return True
        except Database.Exception:
            Logger.Logger.e1(
                "config", "set", f"connection refused while setting key {key}, database not running", traceback.format_exc())
            exit(1)
        except Exception:
            Logger.Logger.e1(
                "config", "set", f"unknown error while setting key {key}", traceback.format_exc())
            return False

    def get(self, key: str, or_else: any = {}) -> object:
        """
        Get the value of a configuration key.  
        returns `configuration`.`key` or if no entry found `or_else` which defaults to `{}`
        """
        try:
            if self.db.table("config").filter({"key": key}).found:
                return self.db.table("config").filter({"key": key})[0]["value"]
            return or_else
        except Database.Exception:
            Logger.Logger.e1(
                "config", "get", f"connection refused while getting key {key}, database not running", traceback.format_exc())
            exit(1)
        except Exception:
            Logger.Logger.e1(
                "config", "get", f"unknown error while getting key {key}", traceback.format_exc())
            return or_else
