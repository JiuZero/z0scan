#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import inspect
import os
import sys
import threading
from colorama import deinit

from lib.controller.controller import start, task_push_from_name
from lib.core.enums import HTTPMETHOD
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.proxy.baseproxy import AsyncMitmProxy
from lib.parse.cmdparse import cmd_line_parser
from lib.core.data import conf, KB
from lib.core.log import logger, dataToStdout
from lib.core.option import init
from lib.core.console import start_web_console

import warnings

def version_check():
    if sys.version.split()[0][0] == "2":
        logger.error("Incompatible Python version detected ('{}'). To successfully run Z0SCAN you'll have to use version >= 3.9 (visit 'https://www.python.org/downloads/')".format(sys.version.split()[0]))
        sys.exit(0)

def modulePath():
    try:
        if "__compiled__" in globals():
            _ = sys.argv[0]
        elif hasattr(sys, "frozen"):
            _ = sys.executable
        else:
            _ = __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)
    abs_path = os.path.realpath(_)
    dir_path = os.path.dirname(abs_path)
    return dir_path

def main():
    version_check()

    # init
    root = modulePath()
    cmdline = cmd_line_parser()
    init(root, cmdline)

    # 主动爬虫的被动扫描
    if conf.enable_crawler:
        KB["continue"] = True
        # 启动漏洞扫描器
        scanner = threading.Thread(target=start)
        scanner.daemon = True
        scanner.start()
        logger.info("Running in DIRECT SCAN mode with CRAWLER")
        # 启动代理服务器
        baseproxy = AsyncMitmProxy(server_addr=conf.server_addr, https=True)
        proxy_thread = threading.Thread(target=baseproxy.serve_forever)
        proxy_thread.daemon = True
        proxy_thread.start()
        if conf.url:
            urls = []
            urls.append(conf.url)
        elif conf.url_file:
            urlfile = conf.url_file
            if not os.path.exists(urlfile):
                logger.error("File:{} don't exists".format(urlfile))
                sys.exit(0)
            with open(urlfile) as f:
                _urls = f.readlines()
            _urls = [i.strip() for i in _urls]
            urls.extend(_urls)
        if urls == []:
            sys.exit()
        try:
            try:
                from lib.core.crawler import Crawlergo
                crawlergo = Crawlergo()
                for url in urls:
                    logger.info(f"Crawler target: {url}")
                    result = crawlergo.crawl(url)
                    logger.info(f"Completed: {url}; Requests: {len(result)}")
            except Exception as e:
                logger.error(f"Failed to start crawler: {e}")
                sys.exit(1)
            KB["continue"] = False
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
        finally:
            # 清理资源
            KB["continue"] = False
            threading.Thread(target=baseproxy.shutdown, daemon=True).start()
            proxy_thread.join(2)
            deinit()
            logger.info("Crawler mode shutdown complete")
    
    # 主动扫描
    elif conf.url or conf.url_file:
        logger.info("Running in DIRECT SCAN mode")
        urls = []
        if conf.url:
            urls.append(conf.url)
        elif conf.url_file:
            urlfile = conf.url_file
            if not os.path.exists(urlfile):
                logger.error("File:{} don't exists".format(urlfile))
                sys.exit(0)
            with open(urlfile) as f:
                _urls = f.readlines()
            _urls = [i.strip() for i in _urls]
            urls.extend(_urls)
        if urls == []:
            sys.exit()
        import requests
        for url in urls:
            try:
                headers = conf.custom_headers if conf.get("custom_headers", False) else None
                cookies = conf.custom_cookies if conf.get("custom_cookies", False) else None
                req = requests.get(url, headers=headers, cookies=cookies)
            except Exception as e:
                logger.error("Request {} faild, {}".format(url, str(e)))
                continue
            fake_req = FakeReq(url, {}, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push_from_name('loader', fake_req, fake_resp)
        start()
    
    # 被动扫描
    elif conf.server_addr:
        logger.info("Running in PASSIVE SCAN mode")
        server = start_web_console(host="127.0.0.1", port=conf.console_port)
        KB["continue"] = True
        # 启动漏洞扫描器
        scanner = threading.Thread(target=start)
        scanner.daemon = True
        scanner.start()
        # 启动代理服务器
        baseproxy = AsyncMitmProxy(server_addr=conf.server_addr, https=True)
        try:
            baseproxy.serve_forever()
        except KeyboardInterrupt:
            scanner.join(0.1)
            KB["continue"] = False
            threading.Thread(target=baseproxy.shutdown, daemon=True).start()
            deinit()
            logger.warning("User QUIT.")
        baseproxy.server_close()
        
    elif conf.get("redis_server"):
        KB["continue"] = True
        try:
            # 启动漏洞扫描器
            start()
        except KeyboardInterrupt:
            KB["continue"] = False
            deinit()
            logger.warning("User QUIT.")

if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    main()