"""
Copyright (c) 2021 Philipp Scheer
"""


import requests


class Connection:
    """A device communication handler.  
    Applications and devices should use this class to communicate securely with the server"""

    def __init__(self, device_id: str) -> None:
        self.id = device_id

    def request(self, endpoint: str, message: object):
        """Request an API endpoint"""
        return requests.post(f"http://127.0.0.1/{endpoint}", message).json()
