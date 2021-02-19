#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import multiprocessing
import time


class ProcessPool:
    def __init__(self, logging_instance: any = None) -> None:
        self.processes = []
        self.logging_instance = logging_instance

    def terminate(self, p: multiprocessing.Process, name: str, max_tries: int = 3, time_between_tries: int = 5) -> None:
        p.terminate()
        i = 0
        while p.is_alive():
            i += 1
            if i > max_tries:
                if self.logging_instance is not None:
                    self.logging_instance.i(
                        "process", f"killing process '{name}', didn't react to terminate signals")
                p.kill()
                return
            else:
                if self.logging_instance is not None:
                    self.logging_instance.i(
                        "process", f"waiting for the '{name}' process to terminate (try {i})")
                time.sleep(time_between_tries)

    def register(self, target_function: any, process_name: str, args: list = []) -> None:
        p = multiprocessing.Process(
            target=target_function, name=process_name, args=args)
        p.start()
        self.processes.append(p)

    def stop_all(self, logging_instance: any = None) -> None:
        for p in self.processes:
            self.terminate(p, p.name)
