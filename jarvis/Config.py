#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#


from jarvis import Database


class Config:
    def __init__(self) -> None:
        self.db = Database()

    def set(self, key: str, value: object) -> bool:
        if self.db.table("config").filter({"key": key}).found:
            return self.db.table("config").filter({"key": key}).update({
                "value": value
            })
        return self.db.table("config").insert({
            "key": key,
            "value": value
        })

    def get(self, key: str, or_else: object = []) -> object:
        if self.db.table("config").filter({"key": key}).found:
            return self.db.table("config").filter({"key": key})[0]
        return or_else 
