#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/5/7

from copy import deepcopy
import requests, threading
from lib.controller.controller import task_push
from lib.core.common import get_parent_paths, get_links
from lib.core.data import conf, KB
from lib.core.log import logger
from lib.core.waf import detector
from lib.core.enums import HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.core.db import selectdb, insertdb
from lib.core.settings import notAcceptedExt, logoutParams
from lib.helper.paramanalyzer import VulnDetector
from lib.core.portscan import ScanPort

# 欺骗 in 操作
class CheatIn:
    def __contains__(self, item):
        return True
    
class Z0SCAN(PluginBase):
    name = 'loader'
    desc = 'plugin loader'
    
    def audit(self):
        headers = deepcopy(self.requests.headers)
        url = deepcopy(self.requests.url)
        hostname = deepcopy(self.requests.hostname)
        
        # Waf检测
        if not conf.ignore_waf:
            while self.requests.hostname in KB.waf_detecting:
                pass
            KB.waf_detecting.append(self.requests.hostname)
            detector(self)
            KB.waf_detecting.remove(self.requests.hostname)
            if self.fingerprints.waf == "None":
                self.fingerprints.waf = False

        lower_headers = {k.lower(): v.lower() for k, v in self.response.headers.items()}
        for name, values in KB["fingerprint"].items():
            if not getattr(self.fingerprints, name):
                if conf.ignore_fingerprint:
                    _result = CheatIn()
                    setattr(self.fingerprints, name, _result)
                else:
                    _result = []
                    for mod in values:
                        m = mod.fingerprint(self.requests.suffix.lower(), lower_headers, self.response.text)
                        if isinstance(m, str):
                            _result.append(m)
                    if _result:
                        setattr(self.fingerprints, name, _result)

        # PerPage
        if KB["spiderset"].add(url, 'PerPage'):
            task_push('PerPage', self.requests, self.response, self.fingerprints)
            iterdatas = self.generateItemdatas()
            for _ in iterdatas:
                k, v, position = _
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_sql_injection(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_file_access(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_redirect(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_ssrf(k, v)
            
        # PerDir
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            """
            # 由插件内部决策
            if parent_url.count("/") > int(conf.max_dir) + 2:
                return
            """
            if not KB["spiderset"].add(parent_url, 'get_link_directory'):
                continue
            if KB["spiderset"].add(parent_url, 'PerDir'):
                req = requests.get(parent_url, headers=headers, allow_redirects=False)
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerDir', fake_req, fake_resp, self.fingerprints)
                
        # PerDomain
        domain = deepcopy(self.requests.netloc) # 保留端口去重
        if KB["spiderset"].add(domain, 'PerDomain'):
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push('PerDomain', fake_req, fake_resp, self.fingerprints)
        
        # perhost
        hostname = deepcopy(self.requests.hostname) # 无端口去重
        if KB["spiderset"].add(hostname, 'perhost'):
            ScanPort(hostname).run()