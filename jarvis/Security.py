#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import hashlib
import random


class Security:
    @staticmethod
    def password_hash(pwd: str):
        return hashlib.sha512(pwd.encode("utf-8")).hexdigest()

    @staticmethod
    def id(len: int = 32, begin: str = "") -> str:
        """Generate a random id
        `len` specifies the length of the id, this can also be a `str`:
            * "micro" == 8
            * "mini" == 16
            * "small" == 32
            * "medium" == 68
            * "large" == 128
            * "critical" == 256
        """
        if isinstance(len, str):
            try:
                len = {
                    "micro": 8,
                    "mini": 16,
                    "small": 32,
                    "medium": 64,
                    "large": 128,
                    "critical": 256
                }[len]
            except KeyError:
                len = 32
        return begin + ''.join(random.choice("0123456789abcdef") for _ in range(len))