#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

from copy import deepcopy
import requests
from lib.controller.controller import task_push
from lib.core.common import get_parent_paths
from lib.core.data import conf, KB
from lib.core.log import logger, colors
from lib.core.fingers import waf, finger
from lib.core.enums import HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from helper.paramanalyzer import VulnDetector
from lib.core.portscan import ScanPort
from time import sleep
from lib.core.thirdpart import API

# 欺骗 in 操作
class CheatIn:
    def __contains__(self, item):
        return True

class Z0SCAN(PluginBase):
    name = 'loader'
    desc = 'plugin loader'
    risk = 3
                            
    def audit(self):
        headers = deepcopy(self.requests.headers)
        url = deepcopy(self.requests.url)
        hostname = deepcopy(self.requests.hostname)
        
        # Waf检测
        if not conf.ignore_waf:
            while self.requests.hostname in KB.waf_detecting:
                sleep(0.5)
            KB.waf_detecting.append(self.requests.hostname)
            self.fingerprints.waf = waf({
                "headers": self.requests.headers, 
                "protocol": self.requests.protocol, 
                "hostname": self.requests.hostname, 
                "port": self.requests.port, 
                "raw": self.requests.raw, 
                "url": self.requests.url
            }).detector()
            KB.waf_detecting.remove(self.requests.hostname)
        else:
            self.fingerprints.waf = False

        # Scanner Payload指导性指纹检测
        if not conf.level == 3:
            self.fingerprints.finger = finger({
                "headers": self.response.headers, 
                "body": self.response.text, 
                "url": self.requests.url, 
            }).detector()
        else:
            self.fingerprints.finger = CheatIn()

        # PerDomain
        domain = deepcopy(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port)) # 保留端口去重
        if KB["spiderset"].add(domain, 'PerDomain'):
            if not conf.skip_pocscan or self.fingerprints.waf:
                vulns = KB.pocscan.scan(domain)
                if vulns != [] and vulns is not None:
                    for _vuln in vulns:
                        result = self.generate_result()
                        result.main(_vuln)
                        self.success(result)
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            # 主页面指纹嗅探
            task_push('PerDomain', fake_req, fake_resp, self.fingerprints)
            
        # PerPage
        if KB["spiderset"].add(url, 'PerPage'):
            # 请求页面指纹嗅探
            iterdatas = self.generateItemdatas()
            for _ in iterdatas:
                k, v, position = _
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_sql_injection(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_file_access(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_redirect(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_ssrf(k, v)
            task_push('PerPage', self.requests, self.response, self.fingerprints)
            
        # PerDir
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            """
            # 由插件内部决策
            if parent_url.count("/") > int(conf.max_dir) + 2:
                return
            """
            if KB["spiderset"].add(parent_url, 'PerDir'):
                req = requests.get(parent_url, headers=headers, allow_redirects=False)
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerDir', fake_req, fake_resp, self.fingerprints)
        
        # PerHost
        ip = deepcopy(self.requests.ip) # 无端口去重
        if KB["spiderset"].add(ip, 'PerHost'):
            ScanPort(ip).run()