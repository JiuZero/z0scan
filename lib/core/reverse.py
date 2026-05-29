#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/5

import threading
import time
import platform
from lib.core.data import conf
from lib.core.log import logger
from lib.reverse.reverse_http import http_start
from lib.reverse.reverse_rmi import rmi_start
from lib.reverse.reverse_dns import dns_start
from lib.reverse.reverse_ldap import ldap_start


def reverse_main():
    th = []
    funcs = [http_start]
    if not conf.command == "reverse_client":
        if conf.reverse.get("dns_enable") is True:
            funcs += [dns_start]
        if conf.reverse.get("rmi_enable") is True:
            funcs += [rmi_start]
        if conf.reverse.get("ldap_enable") is True:
            funcs += [ldap_start]
    for func in funcs:
        thread = threading.Thread(target=func)
        thread.setDaemon(True)
        thread.start()
        th.append(thread)
        time.sleep(0.5)
    try:
        while True:
            time.sleep(1.5)
    except KeyboardInterrupt:
        logger.info("User Quit.")
    finally:
        pass

if __name__ == '__main__':
    reverse_main()
