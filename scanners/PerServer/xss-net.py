#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay
# JiuZero 2025/3/3

from urllib.parse import urlparse
import requests

from api import conf, KB, random_str, generateResponse, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "xss-net"
    desc = '.NET XSS'
    version = "2025.3.3"
    risk = 1
    
    def audit(self):
        if self.risk in conf.risk and conf.level != 0 and not self.fingerprints.waf and not self.name in KB.disable:
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
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": req.url, 
                        "vultype": VulType.XSS
                        })
                    result.step("Request1", {
                        "request": req.reqinfo, 
                        "response": generateResponse(req), 
                        "desc": "Payload:{} Display on the page".format(payload)
                        })
                    result.step("Request2", {
                        "request": req2.reqinfo, 
                        "response": generateResponse(req2), 
                        "desc": "Payload:{} Display on the page".format(payload)
                        })
                    self.success(result)
