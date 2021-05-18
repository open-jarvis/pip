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
        self.db = Database.Database(exit_on_fail=False)

    def set(self, key: str, value: object) -> bool:
        """
        Set a configuration key to a given value.  
        Sets `key` = `value`
        """
        try:
            res = self.db.table("config").find({ "key": { "$eq": key }})
            if res.found:
                res.update({
                    "value": value
                })
            else:
                self.db.table("config").insert({
                    "key": key,
                    "value": value
                })
            return True
        except Database.Database.Exception:
            Logger.Logger.e1("Config", "Set", f"Connection refused while setting key '{key}', database not running", traceback.format_exc())
        except Exception:
            Logger.Logger.e1("Config", "Set", f"Unknown error while setting key '{key}'", traceback.format_exc())
        return False

    def get(self, key: str, or_else: any = {}) -> object:
        """
        Get the value of a configuration key.  
        Returns `configuration`.`key` or if no entry found `or_else` which defaults to `{}`
        """
        try:
            res = self.db.table("config").find({"key": {"$eq": key}})
            if res.found:
                return res[0]["value"]
            return or_else
        except Database.Database.Exception:
            Logger.Logger.e1("Config", "Get", f"Connection refused while getting key '{key}', database not running", traceback.format_exc())
        except Exception:
            Logger.Logger.e1("Config", "Get", f"Unknown error while getting key '{key}'", traceback.format_exc())
        return or_else
