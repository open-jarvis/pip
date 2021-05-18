"""
Copyright (c) 2021 Philipp Scheer
"""


import time
import signal
from typing import Callable


class Exiter:
    """
    The Exiter class runs a given script as long as no keyboard interrupt or other exceptions occured
    """
    
    running = True
    """
    Specifies if the got stopped by the user or not.  
    As long as `running` is True, the script may continue running  
    If `running` is False, the script knows its parent process or itself got stopped and can safely exit
    """

    exit_fn_list = []
    """
    Contains a list of callbacks which get executed when the script stops
    """

    def __init__(self, on_exit_fn: Callable, args: object = None) -> None:
        """
        Initialize the Exiter class
        * `on_exit_fn` is a callable which gets added to the `exit_fn_list` and gets called whenever the parent or current process stops
        * `args` specifies args which should be passed to the `on_exit_fn`
        """
        Exiter.exit_fn_list.append({"fn": on_exit_fn, "args": args})

    @staticmethod
    def mainloop(sleep_interval=1):
        while Exiter.running:
            time.sleep(sleep_interval)

    @staticmethod
    def exit_fn(signum: int, frame: str) -> None:
        """
        A callback function for the signal.signal handlers
        """
        Exiter.running = False
        for fn in Exiter.exit_fn_list:
            fn["fn"]() if fn["args"] is None else fn["fn"](*fn["args"])


signal.signal(signal.SIGINT, Exiter.exit_fn)
signal.signal(signal.SIGTERM, Exiter.exit_fn)
