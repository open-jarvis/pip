#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import signal
from typing import Callable


class Exiter:
    running = True
    exit_fn_list = []

    def __init__(self, on_exit_fn: Callable, args: object = None) -> None:
        # print(f"Exiter({on_exit_fn.__name__}())")
        Exiter.exit_fn_list.append({"fn": on_exit_fn, "args": args})

    @staticmethod
    def exit_fn(signum: int, frame: str) -> None:
        Exiter.running = False
        for fn in Exiter.exit_fn_list:
            # print(f"Exiter: running {fn['fn'].__name__}")
            fn["fn"]() if fn["args"] is None else fn["fn"](*fn["args"])


signal.signal(signal.SIGINT, Exiter.exit_fn)
signal.signal(signal.SIGTERM, Exiter.exit_fn)
