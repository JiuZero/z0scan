#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : cmdparse.py

import argparse
import os
import sys


def cmd_line_parser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    _ = os.path.basename(argv[0])
    usage = "z0scan [options]"
    parser = argparse.ArgumentParser(prog='Z0SCAN', usage=usage)
    parser.add_argument("-v", "--version", dest="version", action="store_true", help="Show program's version number and exit")
    parser.add_argument("--debug", dest="debug", action="store_true", help="Show programs's exception")
    parser.add_argument("-l", "--level", dest="level", type=int, choices=list(range(1, 5)), help="Different level use different payload: 1-4(The default numbers see config.py)")
    # Proxy options
    proxy = parser.add_argument_group('Proxy', 'Passive Agent Mode Options')
    proxy.add_argument("-s", "--server-addr", dest="server_addr", help="Server addr format:(ip:port) ")
    # Target options
    target = parser.add_argument_group('Target', "Options has to be provided to define the target(s)")
    target.add_argument("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")
    target.add_argument("-f", "--file", dest="url_file", help="Scan multiple targets given in a textual file")
    # Requests options
    request = parser.add_argument_group("Request", "Network request options")
    request.add_argument("-p", "--proxy", dest="proxy", help="Use a proxy to connect to the target URL,Support http,https,socks5,socks4 eg:http@127.0.0.1:8080 or socks5@127.0.0.1:1080")
    request.add_argument("--timeout", dest="timeout", help="Seconds to wait before timeout connection(The default numbers see config.py)", type=int)
    request.add_argument("--retry", dest="retry", type=int, help="Time out retrials times(The default numbers see config.py)")
    request.add_argument("--random-agent", dest="random_agent", action="store_true", default=False, help="Use randomly selected HTTP User-Agent header value")
    # Outout options
    output = parser.add_argument_group("Output", "Output options")
    output.add_argument("--html", dest="html", help="When selected, the output will be output to the output directory by default, or you can specify", action='store_true')
    output.add_argument("--json", dest="json", help="The json file is generated by default in the output directory, you can change the path")
    # Optimization options
    optimization = parser.add_argument_group("Optimization", "Optimization options")
    optimization.add_argument('-t', "--threads", dest="threads", type=int, help="Max number of concurrent network requests(The default numbers see config.py)")
    optimization.add_argument('--disable', dest='disable', nargs='+', default=[], help="Disable some plugins (e.g. --disable xss webpack)")
    optimization.add_argument('--able', dest='able', nargs='+', default=[], help="Enable some moudle (e.g. --enable xss webpack)")
    optimization.add_argument('--ignore-waf', dest='ignore_waf', action="store_true", default=False, help="Ignore the WAF for detection")

    args = parser.parse_args()
    dd = args.__dict__
    if not any((dd.get("server_addr"), dd.get("url"), dd.get("url_file"), dd.get("version"))):
        errMsg = "missing a mandatory option (-s, --server-addr, -u, -f, -r, --url, --file). "
        errMsg += "Use -h for basic and -hh for advanced help\n"
        parser.error(errMsg)
    return dd
