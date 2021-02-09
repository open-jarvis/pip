#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

from typing import Any
import couchdb2

TABLES = ["config", "devices", "apps", "instants", "tokens", "brain", "logs"]
DATABASE = "jarvis"


class DatabaseConnection:
    def __init__(self, username: str, password: str, hostname: str = "127.0.0.1", port: int = 5984) -> None:
        self.host = hostname
        self.port = port
        self.user = username

        self.server = couchdb2.Server(
            f"http://{self.host}:{self.port}/", username=self.user, password=password)

    def database(self, name: str):
        return Database(self.server, name)

    def is_up(self):
        return self.server.up()


class Database:
    def __init__(self, server: couchdb2.Server, name: str) -> None:
        self.server = server
        self.name = name

    def table(self, name: str):
        # A database is also a table in couchdb, so we make a trick:
        #   prefix all tables with a given database name
        return Table(self.server, f"{self.name}-{name}")


class Table:
    def __init__(self, server: couchdb2.Server, name: str) -> None:
        self.server = server
        self.name = name
        if self.name in self.server:
            self.table = self.server.get(name)
        else:
            self.table = self.server.create(name)

    def get(self, id: str) -> dict:
        return self.table.get(id)

    def get_all(self) -> list:
        all = []
        for doc in self.table:
            all.append(doc)
        return all

    def insert(self, document: dict) -> any:
        return self.table.put(document)
