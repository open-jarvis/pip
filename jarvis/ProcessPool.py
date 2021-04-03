#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import multiprocessing
import time


class ProcessPool:
    """
    ProcessPool stores a list of background processes and provides several features to control these processes
    """

    def __init__(self, logging_instance: any = None) -> None:
        """
        Initialize an empty ProcessPool with a given `logging_instance`  
        `logging_instance` should be a `Logger` instance
        """
        self.processes = []
        self.logging_instance = logging_instance

    def terminate(self, p: multiprocessing.Process, name: str, grace_period: int = 2) -> None:
        """
        Terminate a p `process` with a given `name`
        * `max_tries` specifies the max tries with a terminate signal before killing the process
        * `time_between_tries` sets the seconds between each try
        """
        p.terminate()
        if self.logging_instance is not None:
            self.logging_instance.i(
                "process", f"waiting for process '{name}' to terminate, grace period of {grace_period}s")
        time.sleep(grace_period)
        if p.is_alive():
            if self.logging_instance is not None:
                self.logging_instance.i(
                    "process", f"killing process '{name}', grace period of {grace_period}s is over")
            p.kill()

    def register(self, target_function: any, process_name: str, args: list = []) -> None:
        """
        Register a background process and add it to the ProcessPool
        * `target_function` specifies the function which should be run in background
        * `process_name` specifies a short and descriptive name what this function is doing
        * `args` specifies a list of arguments which should be passed to the function
        """
        p = multiprocessing.Process(
            target=target_function, name=process_name, args=args)
        p.start()
        self.processes.append(p)

    def stop_all(self, grace_period: int = 2) -> None:
        """
        Stop all processes in the ProcessPool  
        Try terminating the processes before killing them
        """
        for p in self.processes:
            self.terminate(p, p.name, grace_period)
