#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import types
import couchdb2


config = {
    "TABLES": ["config", "devices", "apps", "instants", "tokens", "brain", "logs"],
    "DATABASE": "jarvis"
}


class Database:
    def __init__(self, username: str = "jarvis", password: str = "jarvis", name: str = "jarvis", hostname: str = "127.0.0.1", port: int = 5984) -> None:
        self.host = hostname
        self.port = port
        self.user = username
        self.name = name

        self.server = couchdb2.Server(
            f"http://{self.host}:{self.port}/", username=self.user, password=password)

    def table(self, name: str, pure: bool = False):
        # A database is also a table in couchdb, so we make a trick:
        #   prefix all tables with a given database name
        return Table(self.server, f"{self.name}-{name}") if not pure else Table(self.server, name)

    @property
    def up(self):
        return self.server.up()


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

    def all(self) -> list:
        doc_list = DocumentList(self)
        for doc in self.table:
            doc_list.add(doc)
        return doc_list

    def insert(self, document: dict) -> any:
        return self.table.put(document)

    def filter(self, filter: any = {}) -> list:
        """
        Filters a table
        `filter` can be either a lamba or object
        """
        doc_list = DocumentList(self)
        if (isinstance(filter, types.LambdaType)):
            for document in self.get_all():
                if filter.__call__(document):
                    doc_list.add(document)
        if (isinstance(filter, dict)):
            for document in self.get_all():
                for key in filter:
                    if key in document and document[key] == filter[key]:
                        doc_list.add(document)
        return doc_list

    def delete(self):
        self.table.destroy()


class DocumentList:
    def __init__(self, table: Table, document_list: list = []) -> None:
        self.table = table
        self.document_list = document_list

    def add(self, item_or_list: any, append_lists=False):
        if (isinstance(item_or_list, list)) and not append_lists:
            for item in list:
                self.add(item, True)
        else:
            self.document_list.append(item_or_list)

    def update(self, new_document: dict):
        for document in self.document_list:
            if "_id" not in new_document:
                new_document["_id"] = document["_id"]
                new_document["_rev"] = document["_rev"]
            self.table.insert(new_document)
        pass

    def delete(self):
        for document in self.document_list:
            self.table.table.delete(document)

    @property
    def found(self):
        return len(self.document_list) != 0

    def __getitem__(self, key: int):
        return self.document_list[key]
