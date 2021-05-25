"""
Copyright (c) 2021 Philipp Scheer
"""


from threading import Thread


class ThreadPool:
    """
    ThreadPool stores a list of background threads and provides several features to control these threads
    """

    def __init__(self, logging_instance: any = None) -> None:
        """
        Initialize an empty ThreadPool with a given `logging_instance`  
        `logging_instance` should be a `Logger` instance
        """
        self.threads = []
        self.logging_instance = logging_instance

    def register(self, target_function: any, thread_name: str, args: list = []) -> None:
        """
        Register a background thread and add it to the ThreadPool
        * `target_function` specifies the function which should be run in background
        * `thread_name` specifies a short and descriptive name what this function is doing
        * `args` specifies a list of arguments which should be passed to the function
        """
        t = Thread(target=target_function, name=thread_name, args=args)
        t.start()
        self.threads.append(t)

    def stop_all(self, grace_period: int = 2) -> None:
        """
        Stop all threads in the ThreadPool  
        Try terminating the threads before killing them
        HAS NO EFFECT!
        """
        return True
