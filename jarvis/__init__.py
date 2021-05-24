"""
## Helper Module

### List of classes:
* [API](jarvis/API.html)
* [MQTT](jarvis/MQTT.html)
* [Client](jarvis/Client.html)
* [Colors](jarvis/Colors.html)
* [Config](jarvis/Config.html)
* [Crypto](jarvis/Crypto.html)
* [Protocol](jarvis/Protocol.html)
* [SetupTools](jarvis/SetupTools.html)
* [Exiter](jarvis/Exiter.html)
* [Mime](jarvis/Mime.html)
* [Security](jarvis/Security.html)
* [ThreadPool](jarvis/ThreadPool.html)
* [Logger](jarvis/Logger.html)
* [Database](jarvis/Database.html)
"""

from .API import *
from .MQTT import *
from .Client import *
from .Colors import *
from .Config import *
from .Crypto import *
from .Protocol import *
from .SetupTools import *
from .Exiter import *
from .Mime import *
from .Security import *
from .ThreadPool import *
from .Logger import *
from .Database import *

def update():
    try:
        from pip._internal import main as pipmain
        pipmain(["install", "--upgrade", "--no-deps", "open-jarvis"])
    except Exception:
        print("WARNING: pip could not update, not critical")
