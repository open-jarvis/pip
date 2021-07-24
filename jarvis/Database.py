#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import types
import couchdb2
import requests
import traceback
import time
from functools import wraps


def benchmark(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        if end-start > 1:
            print(f"Database::{func.__name__} took {end-start}s")
        return res
    return wrap


class Database:
    """
    A Database class which handles DB connections and exceptions
    """

    Exception = (requests.ConnectionError, Exception)
    """
    An exception or a list of exception which might occur while making operations with the Database
    """

    def __init__(self, username: str = "jarvis", password: str = "jarvis", name: str = "jarvis", hostname: str = "127.0.0.1", port: int = 5984, exit_on_fail=True) -> None:
        """
        Creates a Database connection with the following arguments:
        * `username` specifies the database username
        * `password` specifies the database password
        * `name` specifies the database name
        * `hostname` specifies the hostname the database is running on
        * `port` specifies the port the database is running on
        * `exit_on_fail` if this switch is set, exit if the database is not running, default false
        """
        self.host = hostname
        self.port = port
        self.user = username
        self.name = name
        self.server = None

        try:
            self.server = couchdb2.Server(f"http://{self.host}:{self.port}/", username=self.user, password=password)
        except Database.Exception:
            from jarvis.Logger import Logger
            Logger.e1("Database", "Refused", "Connection refused, database not running", traceback.format_exc(), database_entry=False)
            if exit_on_fail:
                exit(1)

    def table(self, table_name: str, pure: bool = False):
        """
        Get a table in the database  
        Because CouchDB does not support tables, all tables are prefixed with the database name `self.name`  
        The final table name therefore is `self.name`-`table_name`  
        If `pure` is True, the final table name is `table_name`
        """
        return Table(self.server, table_name if pure else f"{self.name}-{table_name}")

    def delete(self):
        """Delete the current Database """
        for db in self.server:
            if str(db).startswith(f"{self.name}-"):
                db.destroy()

    def drop(self):
        """Delete the current Database"""
        return self.delete()

    @property
    def stats(self):
        """Contains Database stats"""
        return self.server.get_node_stats(nodename='_local')

    @property
    def up(self):
        """Check if Database is up and running"""
        try:
            return self.server.up()
        except Database.Exception:
            return False

    def __str__(self) -> str:
        """Return string representation of the Database"""
        if not hasattr(self, "name"):
            self.name = "ERROR"
        return f"jarvis.Database.Database({self.name})"


class Table:
    """Represents a Table in a Database  
    This class should never be called by the user, only by the `Database` class"""
    def __init__(self, server: couchdb2.Server, table_name: str) -> None:
        """
        Initialize the table  
        * `server` is a CouchDB instance  
        * `table_name` specifies the table name
        """
        self.server = server
        self.name = table_name
        if self.name in self.server:
            self.table = self.server.get(self.name)
        else:
            self.table = self.server.create(self.name)

    @benchmark
    def get(self, id: str) -> dict:
        """Get a document from the current table by `id`"""
        return self.table.get(id)

    @benchmark
    def all(self) -> list:
        """Return all documents from the current table"""
        all_list = DocumentList(self)
        for doc in self.table:
            all_list.add(dict(doc))
        return all_list

    @benchmark
    def insert(self, document: dict) -> any:
        """Insert a document in the current table"""
        try:
            self.table.put(document)
            return True
        except Database.Exception:
            return False

    @benchmark
    def filter(self, filter: any = {}) -> list:
        """THE USE OF THIS FUNCTION IS DISCOURAGED! USE FIND INSTEAD!
        Filters a table  
        `filter` can be either a lamba or object  
        Returns a list of all documents that match"""
        doc_list = DocumentList(self)
        if (isinstance(filter, types.LambdaType)):
            for document in self.all():
                if filter.__call__(document):
                    doc_list.add(document)
        if (isinstance(filter, dict)):
            if len(filter) == 0:
                return self.all()
            for document in self.all():
                for key in filter:
                    if key in document and document[key] == filter[key]:
                        doc_list.add(document)
        return doc_list

    @benchmark
    def find(self, filter: dict = {}) -> list:
        """Find documents by a <a href="https://pouchdb.com/guides/mango-queries.html">Mango query</a>"""
        doc_list = DocumentList(self)
        doc_list.document_list = self.table.find(filter)["docs"]
        return doc_list

    @benchmark
    def delete(self, document):
        """Delete a document from the table"""
        self.table.purge([document])

    @benchmark
    def drop(self):
        """Drop the current table"""
        return self.table.destroy()

    @property
    def size(self):
        """Return the size of the current table in bytes"""
        info = dict(self.table.get_info())
        return info["sizes"]["active"]
    
    @property
    def count(self):
        info = dict(self.table.get_info())
        return info["doc_count"]

    def __str__(self) -> str:
        """Returns string representation of the current table"""
        if not hasattr(self, "name"):
            self.name = "ERROR"
        return f"jarvis.Database.Table({self.name})"


class DocumentList:
    """
    A list of object with various additional features  
    This class should never be called by the user, only by the `Table` class
    """
    def __init__(self, table: Table) -> None:
        """
        Initialize an empty DocumentList  
        * `table` is a `Table` object which got called by `Database`
        """
        self.table = table
        self.document_list = []

    def add(self, item: dict) -> None:
        """
        Add a document to the DocumentList
        """
        self.document_list.append(item)

    def set(self, new_document: dict) -> None:
        """
        Update a document, the document needs to contain an _id and _rev (CouchDB internals)
        """
        for document in self.document_list:
            if "_id" not in new_document:
                new_document["_id"] = document["_id"]
                new_document["_rev"] = document["_rev"]
            self.table.insert(new_document)

    def update(self, modify_function_or_new_object: any) -> None:
        """
        Update all documents using a function or a dictionary with updated keys  
        The if a function is passed, the object the function returns is used,  
        else the merged dictionaries
        """
        if isinstance(modify_function_or_new_object, dict):
            for document in self.document_list:
                def merge_dicts(x, y):
                    z = x.copy()
                    z.update(y)
                    return z
                self.table.insert(merge_dicts(document, modify_function_or_new_object))
        else:
            for old_document in self.document_list:
                new_document = modify_function_or_new_object(dict(old_document))
                self.table.insert(new_document)

    def delete(self) -> None:
        """
        Delete all documents in the current DocumentList
        """
        for document in self.document_list:
            self.table.delete(document)

    def sort(self, keyname: str) -> None:
        """
        Sort all documents in the current DocumentList by a given `keyname`
        """
        self.document_list = sorted(
            self.document_list, key=lambda k: k[keyname] if keyname in k else 0)
        return self

    def reverse(self):
        """
        Reverse the current DocumentList
        """
        self.document_list.reverse()
        return self

    @property
    def found(self):
        """
        Check if the Table query returned any results (length of the current DocumentList is not 0)
        """
        return len(self.document_list) != 0

    def __getitem__(self, key: int):
        """
        Get element from DocumentList
        """
        return self.document_list[key]

    def __list__(self):
        """
        Return the full DocumentList as a list object
        """
        return self.document_list

    def __str__(self) -> str:
        """
        String representation of the current DocumentList
        """
        if not hasattr(self, "table"):
            self.table = "ERROR"
        if not hasattr(self, "document_list"):
            self.document_list = []
        return f"jarvis.Database.DocumentList(table={str(self.table)}, list={str(self.document_list)})"