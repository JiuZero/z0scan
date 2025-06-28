#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/5

import threading
import time

from lib.reverse.lib import rlog
from lib.reverse.reverse_http import http_start
from lib.reverse.reverse_rmi import rmi_start
from lib.reverse.reverse_dns import dns_start


def reverse_main():
    th = []
    for func in [http_start, rmi_start, dns_start]:
        thread = threading.Thread(target=func)
        thread.setDaemon(True)
        thread.start()
        th.append(thread)
        time.sleep(0.5)

    try:
        while True:
            time.sleep(1.5)
    except KeyboardInterrupt:
        rlog.info("User KeyboardInterrupt")
    finally:
        pass


if __name__ == '__main__':
    reverse_main()
