#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import time
import types
from rethinkdb import RethinkDB

TABLES = ["config", "devices", "applications", "instants", "tokens", "brain", "logs"]
DB_NAME = "jarvis"


class Database:
    @staticmethod
    def create() -> None:
        r = RethinkDB()
        con = r.connect()
        con.noreply_wait()

        r.db_list().contains(DB_NAME).do(lambda x:
                                         r.branch(
                                             x,
                                             {"dbs_created": 0},
                                             r.db_create(DB_NAME)
                                         )).run(con)

        con.use(DB_NAME)

        [r.table_list().contains(tbl).do(lambda x:
                                         r.branch(
                                             x,
                                             {"dbs_created": 0},
                                             r.table_create(tbl)
                                         )).run(con) and time.sleep(1) and print(f"created table {DB_NAME}.'{con}'") for tbl in TABLES]

    @staticmethod
    def get() -> list:
        r = RethinkDB()
        con = r.connect(db="jarvis")
        con.check_open(types.MethodType(Database.auto_reconnect, con))
        con.noreply_wait()
        return [r, con]
    
    @staticmethod
    def auto_reconnect(self):
        if self._instance is None or not self._instance.is_open():
            self.reconnect()

