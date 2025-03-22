#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay
# JiuZero 2025/3/3

from urllib.parse import urlparse
import requests

from api import conf, KB, random_str, generateResponse, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "NetXSS"
    desc = '.NET XSS'
    def condition(self):
        if conf.level == 4 and not KB["WAFSTATE"]:
            return True
        return False
        
    def audit(self):
        if self.condition():
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)

            payload = "(A({}))/".format(random_str(6))
            url = domain + payload

            req = requests.get(url, headers=self.requests.headers)
            if payload in req.text:
                new_payload = "(A(\"onerror='{}'{}))/".format(random_str(6), random_str(6))
                url2 = domain + new_payload
                req2 = requests.get(url2, headers=self.requests.headers)
                if new_payload in req2.text:
                    result = self.new_result()
                    result.init_info(Type.Request, self.requests.hostname, "{} | {}".format(req.url, req2.url), VulType.XSS, PLACE.URL)
                    result.add_detail("Request", req.reqinfo, generateResponse(req), "Payload:{}回显在页面".format(payload))
                    result.add_detail("Request", req2.reqinfo, generateResponse(req2), "Payload:{}回显在页面".format(payload))
                    self.success(result)
