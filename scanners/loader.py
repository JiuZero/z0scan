#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : loader.py

from urllib.parse import urlparse

import requests, re
import config
from lib.controller.controller import task_push
from lib.core.common import isListLike, get_parent_paths
from lib.core.data import conf, KB, logger
from lib.core.checkwaf import CheckWaf
from lib.core.enums import WEB_PLATFORM, OS, HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
from lib.core.db import selectdb, insertdb


class Z0SCAN(PluginBase):
    type = 'loader'
    desc = '''Loader插件对请求以及响应进行解析，从而调度更多插件运行'''
    name = 'plugin loader'

    def audit(self):
        headers = self.requests.headers
        url = self.requests.url
        p = urlparse(url)
        if not p.netloc:
            return
        
        # 跳过一些扫描
        for rule in conf.excludes:
            if rule in p.netloc:
                logger.info("Skip Domain: {}".format(url))
                return
        if config.SKIP_SIMILAR_URL:
            match = r'([/_?&=-])(\d+)'
            replace = "'" + re.sub(match, r'\1\\d+', url) + "'"
            condition = "HOSTNAME='{}' AND (URL REGEXP({}) OR URL='{}')".format(self.requests.hostname, replace, url)
            history = selectdb("SCANNED", "URL", condition=condition)
            if history:
                logger.info("Skip URL: {}".format(url))
                return
        
        cv = {
            'HOSTNAME': self.requests.hostname,
            'URL': url
        }
        insertdb("SCANNED", cv)

        # Waf检测
        if not KB["IGNORE_WAF"]:
            while KB["limit"]:
                pass
            CheckWaf(self)
            KB["limit"] = False

        # 根据后缀判断语言与系统
        exi = self.requests.suffix.lower()
        if exi == ".asp":
            self.response.programing[WEB_PLATFORM.ASP] = None
            self.response.os[OS.WINDOWS] = None
        elif exi == ".aspx":
            self.response.programing[WEB_PLATFORM.ASPX] = None
            self.response.os[OS.WINDOWS] = None
        elif exi == ".php":
            self.response.programing[WEB_PLATFORM.PHP] = None
        elif exi == ".jsp" or exi == ".do" or exi == ".action":
            self.response.programing[WEB_PLATFORM.JAVA] = None
        
        lower_headers = {k.lower(): v for k, v in self.response.headers.items()}
        for name, values in KB["fingerprint"].items():
            for mod in values:
                m, version = mod.fingerprint(lower_headers, self.response.text)
                if isinstance(m, str):
                    if name == "os" and m not in self.response.os:
                        self.response.os[m] = version
                    elif name == "webserver" and m not in self.response.webserver:
                        self.response.webserver[m] = version
                    elif name == "programing" and m not in self.response.programing:
                        self.response.programing[m] = version
                '''
                    if isListLike(m):
                        _result += list(m)
                if _result:
                    setattr(self.response, name, _result)
                '''

        if KB["DEBUG"]:
            iterdatas = self.generateItemdatas()
            logger.debug(iterdatas, origin='iterdatas')


        # PerFile
        if KB["spiderset"].add(url, 'PerFile'):
            task_push('PerFile', self.requests, self.response)

        # PerServer
        p = urlparse(url)
        domain = "{}://{}".format(p.scheme, p.netloc)
        if KB["spiderset"].add(domain, 'PerServer'):
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push('PerServer', fake_req, fake_resp)

        # PerFolder
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            if not KB["spiderset"].add(parent_url, 'get_link_directory'):
                continue
            req = requests.get(parent_url, headers=headers, allow_redirects=False)
            if KB["spiderset"].add(req.url, 'PerFolder'):
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerFolder', fake_req, fake_resp)
