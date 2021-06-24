"""
Copyright (c) 2021 Philipp Scheer
"""


import re
import os
import sys
import time
import inspect
import traceback
from collections import OrderedDict
from jarvis.MQTT import MQTT
from jarvis.Logger import Logger


logger = Logger("API")


class API():
    """
    API helper class to register MQTT routes

    Example usage:  
    ```python
    @API.route("jarvis/ping")
    def serve_ping(*args, **kwargs):
        return "pong"
    
    @API.route("jarvis/status")
    def serve_status(args, data, use_json=True):
        return { "status": True } if use_json else True
    
    @API.route("jarvis/exception")
    def serve_test_exception(args, data):
        raise Exception("This is a test") # will get caught by API and converted to 'This is a test'
    
    @API.route("jarvis/client/+/ping")
    def serve_client_ping(args, data):
        client_id = args[0]
        return f"client {client_id} is up!"
    ```

    If you want to execute an API endpoint, use:
    ```python
    result = API.execute("jarvis/status", data)
    # { "status": True }
    ```"""

    AUTO_GENERATE_DOCUMENTATION = "APIDOC.py"
    """Automatically generate a documentation when code snippets register API endpoints  
    If you **do not** want to autogenerate a documentation, set to `False`  
    Otherwise, specify an absolute or relative path to the documentation file  
    The relative file will be placed in `/jarvis/server/<path>`  
    Documentation output format is Markdown for .md files and pydoc for .py files"""

    DOCUMENTATION = {}
    """A dictionary containing all the function documentations  
    Format: { `<endpoint>`: `<documentation>` }"""

    routes = {}
    """A dictionary containing all registered routes"""

    @staticmethod
    def _get(route: str):
        """Get a route from array, else return the default route"""
        for subscription in API.routes:
            if MQTT.match(subscription, route):
                reg = subscription.replace("+", "([^/]+)").replace("#", "([^ ]+)")
                res = re.search(reg, route)
                if res:
                    return (API.routes[subscription], list(res.groups()))
                return (API.routes[subscription], [])
        return (API.default_route, [])

    @staticmethod
    def execute(route: str, *args, **kwargs) -> set:
        """Execute a route with given arguments  
        Returns a tuple with `(True|False, object result)`"""
        start = time.time()
        try:
            endpoint = API._get(route)
            res = endpoint[0](endpoint[1], *args, **kwargs)
            logger.d("Timing", f"Executing route '{route}' took {time.time()-start :.2f}s")
            if isinstance(res, bool):
                return (res, None)
            return (True, res)    
        except Exception as e:
            logger.e("Endpoint", f"Exception occured in endpoint {route}", traceback.format_exc())
            logger.d("Timing",   f"Executing route '{route}' took {time.time()-start :.2f}s")
            return (False, str(e))

    @staticmethod
    def default_route(args, client, data):
        """This is the default route and gets handled if no function was found for route"""
        raise Exception("Endpoint not found")

    @staticmethod
    def route(path):
        """Decorator to register a route  
        [See usage](#API)"""
        def decor(func):
            API.DOCUMENTATION[path] = func.__doc__
            API._save_docs()
            def wrap(*args, **kwargs):
                res = func(*args, **kwargs)
                return res
            API.routes[path] = wrap
            return wrap
        return decor

    @staticmethod
    def _save_docs() -> None:
        to_file = API.AUTO_GENERATE_DOCUMENTATION
        if not to_file.startswith("/"):
            to_file = f"{os.path.dirname(os.path.abspath(sys.argv[0]))}/{API.AUTO_GENERATE_DOCUMENTATION}"
        try:
            with open(to_file, "w") as f:
                if API.AUTO_GENERATE_DOCUMENTATION.lower().endswith(".md"):
                    f.write("# API Documentation\n\n")
                    doc = OrderedDict(sorted(API.DOCUMENTATION.items()))
                    for e, d in doc.items():
                        f.write(f"## `{e}`  \n\n{d}\n\n")
                elif API.AUTO_GENERATE_DOCUMENTATION.lower().endswith(".py"):
                    f.write('"""\nCopyright (c) 2021 Philipp Scheer\n"""\n\nclass APIDOC:\n')
                    doc = OrderedDict(sorted(API.DOCUMENTATION.items()))
                    for e, d in doc.items():
                        try:
                            d = inspect.cleandoc(d)
                        except Exception:
                            d = "No documentation available!"
                        f.write(f'    def {e.replace("/", "_")}():\n        """\n`{e}`\n\n{d}"""\n\n')
        except Exception:
            print(traceback.format_exc())
