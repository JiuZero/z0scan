#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import inspect
import os
import sys
import threading
import requests
from colorama import deinit
from urllib.parse import urlparse

from lib.controller.controller import start, task_push_from_name
from lib.core.enums import HTTPMETHOD

from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.proxy.baseproxy import AsyncMitmProxy

from lib.parse.cmdparse import cmd_line_parser
from lib.core.data import conf, KB
from lib.core.log import logger, dataToStdout
from lib.core.option import init
from lib.core.settings import banner
from lib.core.console import start_web_console
from lib.core.crawler import Crawler

def version_check():
    # Check Python version
    if sys.version.split()[0][0] == "2":
        logger.error("Incompatible Python version detected ('{}'). To successfully run Z0SCAN you'll have to use version >= 3.6 (visit 'https://www.python.org/downloads/')".format(sys.version.split()[0]))
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

def crawl(url):
    logger.warning("Under maintenance, temporarily unavailable.")
    sys.exit(0)
    crawler = Crawler(
        max_depth=int(conf.crawl),
        threads=int(conf.crawl_threads),
        # exclude_pattern=conf.exclude,
        # include_pattern=conf.include
    )
    pages = crawler.crawl(url)
    urls = []
    for page in pages:
        parsed_url = urlparse(page['url'])
        normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        if normalized_url not in urls:
            urls.append(normalized_url)
    logger.info(f"Crawl finish. Found pages: {len(urls)}.")
    # 爬虫与扫描异步进行？如果流量竞争怎么办…
    return urls

def main():
    version_check()

    # init
    root = modulePath()
    cmdline = cmd_line_parser()
    init(root, cmdline)

    if conf.url or conf.url_file:
        urls = []
        if conf.url:
            if not conf.crawl:
                urls.append(conf.url)
            else:
                urls = crawl(conf.url)
        elif conf.url_file:
            urlfile = conf.url_file
            if not os.path.exists(urlfile):
                logger.error("File:{} don't exists".format(urlfile))
                sys.exit(0)
            with open(urlfile) as f:
                _urls = f.readlines()
            _urls = [i.strip() for i in _urls]
            if not conf.crawl:
                urls.extend(_urls)
            else:
                for url in _urls:
                    urls.extend(crawl(url))
        for url in urls:
            try:
                req = requests.get(url)
            except Exception as e:
                logger.error("Request {} faild, {}".format(url, str(e)))
                continue
            fake_req = FakeReq(url, {}, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push_from_name('loader', fake_req, fake_resp)
        start()
    elif conf.server_addr:
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
            scanner.join(0.1)
            KB["continue"] = False
            deinit()
            logger.warning("User QUIT.")

if __name__ == '__main__':
    main()
