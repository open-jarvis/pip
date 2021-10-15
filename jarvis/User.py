"""
Copyright (c) 2021 Philipp Scheer
"""


import time
import json
import random
import traceback
import jinja2
from jarvis import Database, Security, Config


class User:
    def __init__(self, id=None, username=None, password=None, _id=None, **data) -> None:
        self.id = id or _id
        self.username = username
        self.password = password
        self.data = data

    def save(self):
        try:
            old_user = User.from_id(self.id)
            ud = { **self.data,
                "username": self.username,
                "password": self.password,
            }
            if old_user: # we need to get the _rev and id
                ud = { **ud,
                    "_rev": old_user._rev,
                    "_id": old_user.id
                }
            Database().table("users").insert(ud)
            self.id = ud["_id"]
            return ud["_id"]
        except Exception:
            return False

    def to_json(self):
        return self.__dict__()

    def get(self, key, or_else):
        return self.__dict__().get(key, or_else)

    @classmethod
    def new(cls, username, password, **additional_data):
        if User.exists(username):
            return None
        obj = {
            **additional_data,
            "username": username,
            "password": User.hash(password)
        }
        user = cls(**obj)
        user.save()
        return user

    @classmethod
    def from_id(cls, id):
        res = Database().table("users").find({ "_id": { "$eq": id } })
        if res.found:
            res = res[0]
            return cls(**res)
        return None
    
    @classmethod
    def from_email(cls, email):
        res = Database().table("users").find({ "email": { "$eq": email }})
        if res.found:
            res = res[0]
            return cls(**res)
        return None

    @classmethod
    def from_json(cls, jsonObject: dict):
        if isinstance(jsonObject, str):
            jsonObject = json.loads(jsonObject)
        return cls(**jsonObject)

    def __dict__(self):
        return {
            **self.data,
            "id": self.id,
            "username": self.username,
            "password": self.password,
        }

    def __getitem__(self, key):
        return self.__dict__().get(key, None)

    def __getattr__(self, key):
        return self.__dict__().get(key, None)

    @staticmethod
    def validate(username, password):
        result = Database().table("users").find({
            "username": { "$eq": username },
            "password": { "$eq": User.hash(password) }
        })
        if result.found:
            return result[0]["_id"]
        return False
    
    @staticmethod
    def hash(password):
        return Security.password_hash(password)

    @staticmethod
    def exists(username):
        return len(list(Database().table("users").find({ "username": { "$eq": username }}))) > 0
        
    @staticmethod
    def count():
        return len(list(Database().table("users").all()))

