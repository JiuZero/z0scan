#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/5/7

from urllib.parse import urlparse
from copy import deepcopy
import requests, re, os, json
from lib.controller.controller import task_push
from lib.core.common import isListLike, get_parent_paths, get_links
from lib.core.data import conf, KB
from lib.core.log import logger
from lib.core.wafDetector import detector
from lib.core.enums import HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.core.db import selectdb, insertdb
from lib.core.settings import notAcceptedExt, logoutParams
from lib.helper.paramanalyzer import VulnDetector

# 欺骗 in 操作
class CheatIn:
    def __contains__(self, item):
        return True
    
class Z0SCAN(PluginBase):
    name = 'loader'
    desc = 'plugin loader'
    
    def skip(self, url):
        # 跳过用户设置的不扫描目标
        for rule in conf.excludes:
            if rule in self.requests.hostname:
                logger.info("Skip Domain: {}".format(url))
                return True
            
        # 去重
        _raw = self.requests.raw
        if isinstance(_raw, bytes):
            raw_str = _raw.decode('utf-8', errors='ignore')
        else:
            raw_str = _raw
        replaced_str = re.sub(r'\d+', '0', raw_str)
        history = selectdb("cache", "requestsRaw", where="hostname='{}'".format(self.requests.hostname))
        replaced_str = re.sub(r'[\s\n\r]+', '', replaced_str)
        if history == replaced_str and conf.skip_similar_request:
            logger.info("Skip URL: {}".format(url))
            return True
        if history != replaced_str:
            cv = {
                'hostname': self.requests.hostname,
                'requestsRaw': replaced_str
            }
            insertdb("cache", cv)
        return False


    def audit(self):
        if KB.pause:
            return
        headers = deepcopy(self.requests.headers)
        url = deepcopy(self.requests.url)
        hostname = deepcopy(self.requests.hostname)
        
        # Waf检测
        if not conf.ignore_waf:
            while KB.limit:
                pass
            detector(self)
            KB.limit = False
        
        if self.skip(url):
            return

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
        '''
        history = selectdb("info", "fingerprint", where="hostname='{}'".format(hostname))
        if history:
            parts = [p for p in history.split('|') if p]
            for part in parts:
                if '=' in part:
                    name, value_str = part.split('=', 1)
                    try:
                        _result = json.loads(value_str)
                        if not isinstance(_result, list):
                            _result = [_result]
                    except json.JSONDecodeError:
                        pass
                    f = list(getattr(self.fingerprints, name, [])) + _result
                    setattr(self.fingerprints, name, _result)
        _result = []
        for name in dir(self.fingerprints):
            if not name.startswith('_') and not callable(getattr(self.fingerprints, name)):
                value = getattr(self.fingerprints, name, [])
                value_str = json.dumps(value)
                _result.append(f"|{name}={value_str}|")
        _result = str(''.join(_result).replace("||", "|"))
        '''
        cv = {
            'hostname': self.requests.hostname,
            'fingerprint': _result
        }
        insertdb("info", cv)

        iterdatas = self.generateItemdatas()
        for _ in iterdatas:
            k, v, position = _
            VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_sql_injection(k, v)
            VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_file_access(k, v)
            VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_redirect(k, v)
            VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_ssrf(k, v)


        # PerFile
        if KB["spiderset"].add(url, 'PerFile'):
            task_push('PerFile', self.requests, self.response)
            if conf.auto_spider:
                # 二级主动扫描 (深度一级)
                links = get_links(self.requests.content, url, True)
                for link in set(links):
                    try:
                        for item in logoutParams:
                            if item in link.lower():
                                if not KB["spiderset"].inside(link, 'PerFile'):
                                    """
                                    # 超过5M拒绝请求
                                    r = requests.head(link, headers=headers)
                                    if "Content-Length" in r.headers:
                                        if int(r.headers["Content-Length"]) > 1024 * 1024 * 5:
                                            raise Exception("length")
                                    """
                                    p = urlparse(link)
                                    if p.netloc == self.requests.hostname:
                                        exi = os.path.splitext(p.path)[1].lower()
                                        if exi in notAcceptedExt:
                                            raise Exception("exi")
                                        if self.skip(url):
                                            return
                                        r = requests.get(link, headers=headers)
                                        fake_resp = FakeResp(r.status_code, r.content, r.headers)
                                        task_push('PerFile', r, fake_resp)
                                    else:
                                        raise Exception("hostname")
                    except Exception as e:
                        continue

        # PerServer
        domain = deepcopy(self.requests.netloc)
        if KB["spiderset"].add(domain, 'PerServer'):
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push('PerServer', fake_req, fake_resp)
            
        # PerFolder
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            """
            # 由插件内部决策
            if parent_url.count("/") > int(conf.max_dir) + 2:
                return
            """
            if not KB["spiderset"].add(parent_url, 'get_link_directory'):
                continue
            if KB["spiderset"].add(parent_url, 'PerFolder'):
                req = requests.get(parent_url, headers=headers, allow_redirects=False)
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerFolder', fake_req, fake_resp)
