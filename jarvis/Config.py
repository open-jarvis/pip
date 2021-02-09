#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#


from jarvis import Database


class Config:
    def __init__(self) -> None:
        self.r, self.con = Database.get()

    def set(self, key: str, value: object) -> bool:
        result = self.r.table("config").filter({"key": key}).update({
            "value": value
        }).run(self.con) if Database.success(self.r.table("config").filter({"key": key}).run(self.con)) else \
            self.r.table("config").insert({
                "key": key,
                "value": value
            }).run(self.con)
        return result["errors"] is 0 and (result["inserted"] is 1 or result["replaced"] is 1)

    def get(self, key: str, or_else: object = []) -> object:
        result = list(self.r.table("config").filter(
            {"key": key}).run(self.con))
        return or_else if len(result) is 0 else result[0]["value"]
