# !/usr/bin/env python3
# caicai/myscan

import socket
import urllib3
from lib.core.data import conf
from lib.core.log import logger


def allowed_gai_family():
    family = socket.AF_INET
    if conf.ipv6:
        family = socket.AF_UNSPEC
    return family


def ipv6_patch():
    urllib3.util.connection.allowed_gai_family = allowed_gai_family
