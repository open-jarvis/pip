"""
Copyright (c) 2021 Philipp Scheer
"""


import asyncio
from threading import Thread


class ThreadPool:
    """ThreadPool stores a list of background threads and provides several features to control these threads"""

    _all_threads = []

    def __init__(self, logging_instance: any = None) -> None:
        """Initialize an empty ThreadPool with a given `logging_instance`  
        `logging_instance` should be a `Logger` instance"""
        self._threads = []
        self.logging_instance = logging_instance

    def register(self, target_function: any, thread_name: str, args: list = []) -> None:
        """Register a background thread and add it to the ThreadPool
        * `target_function` specifies the function which should be run in background
        * `thread_name` specifies a short and descriptive name what this function is doing
        * `args` specifies a list of arguments which should be passed to the function"""
        t = Thread(target=target_function, name=thread_name, args=args)
        t.start()
        t_object = {
            "name": thread_name,
            "function": target_function,
            "thread": t
        }
        self._threads.append(t_object)
        ThreadPool._all_threads.append(t_object)
    
    def status(self, internal_thread_object: dict = None, thread: Thread = None, thread_name: str = None, target_function: any = None) -> bool:
        """Get the status of a background thread given a Thread object, thread name or target function.  
        Returns a boolean whether it's alive or not and None if not found"""
        if thread is not None:
            return thread.is_alive()
        elif internal_thread_object is not None:
            for t in ThreadPool._all_threads:
                if t["name"] == internal_thread_object.get("name", ""):
                    return t["thread"].is_alive()
        elif thread_name is not None:
            for t in ThreadPool._all_threads:
                if t["name"] == thread_name:
                    return t["thread"].is_alive()
        elif target_function is not None:
            for t in ThreadPool._all_threads:
                if t["function"] == target_function:
                    return t["thread"].is_alive()
        return None
    
    def all(self, include_children: bool = False):
        if include_children:
            return ThreadPool._all_threads
        return self._threads

    @staticmethod
    def background(coroutine, *args):
        def _handle(loop, *args):
            # asyncio.run_coroutine_threadsafe(coroutine(), loop)
            # loop.run_until_complete(coroutine()) # ValueError: The future belongs to a different loop than the one specified as the loop argument
            asyncio.run(coroutine(*args))
        loop = asyncio.new_event_loop()
        t = Thread(target=_handle, args=[loop] + list(args))
        t.start()
