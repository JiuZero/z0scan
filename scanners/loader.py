#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : loader.py

from urllib.parse import urlparse

import requests

from lib.controller.controller import task_push
from lib.core.common import isListLike, get_parent_paths
from lib.core.data import conf, KB, logger
from lib.core.checkwaf import CheckWaf
from lib.core.enums import WEB_PLATFORM, OS, HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp


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
        for rule in conf.excludes:
            if rule in p.netloc:
                logger.info("Skip domain:{}".format(url))
                return

        # Waf检测
        while KB["limit"]:
            pass
        CheckWaf(self)
        KB["limit"] = False

        # 根据后缀判断语言与系统
        exi = self.requests.suffix.lower()
        if exi == ".asp":
            self.response.programing.append(WEB_PLATFORM.ASP)
            self.response.os.append(OS.WINDOWS)
        elif exi == ".aspx":
            self.response.programing.append(WEB_PLATFORM.ASPX)
            self.response.os.append(OS.WINDOWS)
        elif exi == ".php":
            self.response.programing.append(WEB_PLATFORM.PHP)
        elif exi == ".jsp" or exi == ".do" or exi == ".action":
            self.response.programing.append(WEB_PLATFORM.JAVA)

        lower_headers = {k.lower(): v for k, v in self.response.headers.items()}
        for name, values in KB["fingerprint"].items():
            if not getattr(self.response, name):
                _result = []
                for mod in values:
                    m = mod.fingerprint(lower_headers, self.response.text)
                    if isinstance(m, str):
                        _result.append(m)
                    if isListLike(m):
                        _result += list(m)
                if _result:
                    setattr(self.response, name, _result)

        # Fingerprint basic end
        if KB["spiderset"].add(url, 'PerFile'):
            task_push('PerFile', self.requests, self.response)

        # Send PerServer
        p = urlparse(url)
        domain = "{}://{}".format(p.scheme, p.netloc)
        if KB["spiderset"].add(domain, 'PerServer'):
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push('PerServer', fake_req, fake_resp)

        # Collect directory from response
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            if not KB["spiderset"].add(parent_url, 'get_link_directory'):
                continue
            req = requests.get(parent_url, headers=headers, allow_redirects=False)
            if KB["spiderset"].add(req.url, 'PerFolder'):
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerFolder', fake_req, fake_resp)
