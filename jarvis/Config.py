#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#


from jarvis import Database, Logger

class Config:
    def __init__(self) -> None:
        self.db = Database.Database()

    def set(self, key: str, value: object) -> bool:
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
        except Exception as e:
            Logger.e1("config", f"set:{key}", str(e))
            return False

    def get(self, key: str, or_else: any = {}) -> object:
        try:
            if self.db.table("config").filter({"key": key}).found:
                return self.db.table("config").filter({"key": key})[0]
            return or_else 
        except Exception as e:
            Logger.e1("config", f"get:{key}", str(e))
            return False