#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/5/7

from urllib.parse import urlparse
from copy import deepcopy
import requests, re, os
from lib.controller.controller import task_push
from lib.core.common import isListLike, get_parent_paths, get_links
from lib.core.data import conf, KB
from lib.core.log import logger, colors
from lib.core.wafDetector import detector
from lib.core.enums import HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.core.db import selectdb, insertdb
from lib.core.settings import notAcceptedExt, logoutParams

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
                return
            
        # 跳过前台的同一功能页（通常为文章页）
        itemdates = self.generateItemdatas()
        params = ""
        _url = re.sub(r'([/_?&=-])(\d+)', "0", url).split('?')[0]
        _params = {}
        if not len(itemdates) > 6:
            for _ in itemdates:
                k, v, position = _
                if str(v).isdigit():
                    v = "0"
                _params[k] = v
            params = str(sorted(_params.items())).replace('\'', '"')
            history = selectdb("CACHE", "HOSTNAME", where="URL='{}' AND PARAMS='{}'".format(_url, params))
            if history and conf.skip_similar_url:
                logger.info("Skip URL: {}".format(url))
                return True
            if params:
                cv = {
                    'HOSTNAME': self.requests.hostname,
                    'URL': _url,
                    'PARAMS': params,
                }
            else:
                cv = {
                    'HOSTNAME': self.requests.hostname,
                    'URL': _url,
                    'PARAMS': '',
                }
            insertdb("CACHE", cv)
        logger.debug(itemdates, origin='iterdatas', level=1)
        return False


    def audit(self):
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
        # TODO: 对domain指纹进行动态补充

        # PerFile
        if not self.requests.suffix in notAcceptedExt:
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
