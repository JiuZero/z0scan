#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import argparse
import os
import sys
import config
from lib.core.log import logger

def int_list(value):
    try:
        values = list(map(int, value.split(',')))
        for v in values:
            if v not in (-1, 0, 1, 2, 3):
                logger.error(f"Invalid option {v} (allowed values: -1-3).")
                sys.exit(0)
        return values
    except ValueError:
        logger.error("The parameter is in the wrong format, please use comma-separated integers (e.g. 1, 2, 3).")
        sys.exit(0)

def str_list(value):
    try:
        values = list(map(str, value.split(',')))
        return values
    except ValueError:
        logger.error("The parameter is malformed, please use comma-separated characters.")
        sys.exit(0)

def cmd_line_parser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv
        
    _ = os.path.basename(argv[0])
    usage = "z0 [command options] [arguments...]"
    parser = argparse.ArgumentParser(prog='Z0SCAN', usage=usage)
    
    subparsers = parser.add_subparsers(
        dest='command',
        title='Commands', 
        metavar='', 
        help=''
        )
    version_parser = subparsers.add_parser('version', help='Show program\'s version number and exit')
    scan_parser = subparsers.add_parser('scan', help='Scan command with optional crawler mode')
    reverse_parser = subparsers.add_parser('reverse', help='Reverse command')
    list_parser = subparsers.add_parser('list', help='List of plugins and dicts')
    

    ## z0 scan
    # Proxy options
    proxy = scan_parser.add_argument_group('Proxy', 'Passive Agent Mode Options')
    proxy.add_argument("-s", "--server-addr", dest="server_addr", help="Server addr (e.g. --server-addr \"127.0.0.1:5920\").")
    
    # Target options
    target = scan_parser.add_argument_group('Target', "Options has to be provided to define the target(s).")
    target.add_argument("-u", "--url", dest="url", help="Target URL (e.g. --url \"http://www.site.com/vuln.php?id=1\").")
    target.add_argument("-f", "--file", dest="url_file", help="Scan multiple targets given in a textual file.")
    target.add_argument("-Rs", "--redis-server", dest="redis_server", help="Connect to redis, run as server (e.g. --redis-server password@host:port:db).")
    
    # Crawler mode options
    crawler = scan_parser.add_argument_group('Crawler', 'Web crawler mode options (use with -u)')
    crawler.add_argument("--crawler", dest="enable_crawler", action="store_true", default=False, help="Enable crawler mode to discover URLs before scanning.")
    crawler.add_argument("--max-tabs", dest="max_tab_count", type=int, default=8, help="Maximum number of tabs for crawler (Default: 8).")
    crawler.add_argument("--max-crawled", dest="max_crawled_count", type=int, default=200, help="Maximum crawled URL count (Default: 200).")
    crawler.add_argument("--filter-mode", dest="filter_mode", choices=["simple", "smart", "strict"], default="smart", help="URL filter mode for crawler (Default: smart).")
    crawler.add_argument("--tab-timeout", dest="tab_run_timeout", type=int, default=20, help="Single tab timeout in seconds (Default: 20).")
    crawler.add_argument("--dom-timeout", dest="wait_dom_timeout", type=int, default=5, help="DOM load timeout in seconds (Default: 5).")
    
    # Authentication options
    auth = scan_parser.add_argument_group('Authentication', 'Authentication and session options')
    auth.add_argument("--cookies", dest="custom_cookies", help="Custom cookies for crawler (e.g. --cookies \"session=xxx; token=yyy\").")
    auth.add_argument("--headers", dest="custom_headers", help="Custom HTTP headers in JSON format (e.g. --headers '{\"Authorization\": \"Bearer xxx\"}').")
    
    # URL filtering options
    url_filter = scan_parser.add_argument_group('URL Filter', 'URL filtering options for crawler')
    url_filter.add_argument("--ignore-keywords", dest="ignore_url_keywords", type=str_list, default=["logout", "quit", "exit"], help="Ignore URLs with these keywords (Default: logout,quit,exit).")
    
    # Connecton options
    conn = scan_parser.add_argument_group('Connection', 'Server Connection Options')
    conn.add_argument("-R", "--reverse-client", dest="reverse_client", action="store_true", default=False, help="Connect to reverse server. (Default False).")
    conn.add_argument("-Rc", "--redis-client", dest="redis_client", help="Connect to redis, run as client (e.g. --redis-client password@host:port:db).")
    
    # Requests options
    request = scan_parser.add_argument_group("Request", "Network request options")
    request.add_argument("-p", "--proxy", dest="proxy", type=str, help="Use a proxy to connect to the target URL, Support http,https,socks5,socks4 & txt,json (e.g. http://127.0.0.1:8080 or proxy.txt).")
    request.add_argument("--timeout", dest="timeout", default=config.TIMEOUT, help="Seconds to wait before timeout connection (Default {}).".format(config.TIMEOUT), type=int)
    request.add_argument("--retry", dest="retry", type=list, default=config.RETRY, help="Time out retrials times (Default {}).".format(config.RETRY))
    request.add_argument("--random-agent", dest="random_agent", action="store_true", default=False, help="Use randomly selected HTTP User-Agent header value.")
    
    # Passive scanning integration
    passive = scan_parser.add_argument_group('Passive Scanning', 'Integrate crawler with passive scanner')
    passive.add_argument("--push-pool", dest="push_pool_max", type=int, default=10, help="Max concurrent push requests (Default: 10).")
    
    # Output options
    output = scan_parser.add_argument_group("Output", "Output options")
    output.add_argument("--html", dest="html", help="When selected, the output will be output to the output directory by default, or you can specify.", action='store_true')
    output.add_argument("--json", dest="json", help="The json file is generated by default in the output directory, you can change the path.")
    
    # Optimization options
    optimization = scan_parser.add_argument_group("Optimization", "Optimization options")
    optimization.add_argument("-l", "--level", dest="level", type=int, choices=list(range(0, 4)), default=config.LEVEL, help="Different level use different payloads: 0-3 (Default {}) (When the level is 3, the screening of the payload by the guiding fingerprint will be ignored)".format(config.LEVEL))
    optimization.add_argument("-r", "--risk", dest="risk", type=int_list, default=config.RISK, help="Set the threat level of the initialized scanners: [0, 1, 2, 3] (Default {}).".format(config.RISK))
    optimization.add_argument("-i", "--includes", dest="includes", type=str_list, default=[], help="Set whitelist keywords (e.g. --includes com,cn).")
    optimization.add_argument("-e", "--excludes", dest="excludes", type=str_list, default=config.EXCLUDES, help="Set blacklist keywords (e.g. --includes edu.cn,gov.cn).")
    optimization.add_argument('-t', "--threads", dest="threads", type=int, default=config.THREADS, help="Threads of plugins tasks (Default {}).".format(config.THREADS))
    optimization.add_argument("-cp", "--console-port", dest="console_port", type=int, help=f"Set port for console (Default {config.CONSOLE_PORT}).", default=config.CONSOLE_PORT)
    optimization.add_argument('-pt', "--plugin-threads", dest="plugin_threads", type=int, default=config.PLUGIN_THREADS, help="Threads in scanners (Default {}).".format(config.PLUGIN_THREADS))
    optimization.add_argument("-iw", '--ignore-waf', dest='ignore_waf', action="store_true", default=False, help="Ignore the screening of the waf elements during the scanning process.")
    optimization.add_argument("-sp", '--skip-pocscan', dest='skip_pocscan', action="store_true", default=False, help="Skip to scan for POCs by Nuclei.")
    optimization.add_argument("-sc", '--scan-cookie', dest='scan_cookie', action="store_true", default=False, help="Scan cookie during detection.")
    optimization.add_argument("-dl", '--deduplicate-level', dest='deduplicate_level', choices=list(range(0, 3)), type=int, default=config.DEDUPLICATE_LEVEL, help="Deduplication Strategy Level: 0-2 (Default {})".format(config.DEDUPLICATE_LEVEL))
    optimization.add_argument('--disable', dest='disable', type=str_list, default=config.DISLOAD, help="Set scanners not to load.")
    optimization.add_argument('--enable', dest='enable', type=str_list, default=[], help="Set scanners to load only.")
    optimization.add_argument("--ipv6", dest="ipv6", action="store_true", help="Use IPV6 address. It will try for IPV6 at first, else IPV4.")
    optimization.add_argument('--redis-clean', dest='redis_clean', action="store_true", default=False, help="Clean up the data in Redis that has been queued.")
    optimization.add_argument("--debug", dest="debug", type=int, choices=list(range(1, 4)), help="Show programs's exception: 1-3.")
    
    args = parser.parse_args()
    dd = args.__dict__

    if not (dd['command'] in ["version", "reverse", "list", "scan", "update"]):
        errMsg = "An error command input (version, scan, reverse, list, console). "
        errMsg += "Use -h for help\n"
        parser.error(errMsg)

    if args.command == 'scan':
        # 验证基本参数
        if not any((dd.get("server_addr"), dd.get("url"), dd.get("url_file"), dd.get("redis_server"))):
            errMsg = "Missing a mandatory option (-s, --server-addr, -u, --url, -f, --file, -Rs, --redis_server). "
            errMsg += "Use -h for basic and -hh for advanced help\n"
            parser.error(errMsg)
        # crawler 模式，验证必需参数
        if dd.get("enable_crawler"):
            if not dd.get("url"):
                parser.error("Crawler mode requires a single target URL (-u, --url)")
            if not dd.get("server_addr"):
                parser.error("Crawler mode requires to set server_addr (-s, --server-addr)")
            # 解析自定义 headers
            if dd.get("custom_headers"):
                import json
                try:
                    dd["custom_headers"] = json.loads(dd["custom_headers"])
                except json.JSONDecodeError:
                    logger.error("Invalid JSON format for custom headers.")
                    sys.exit(1)
    return args
