#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero/z0scan

from urllib.parse import urlparse
import requests

from api import random_str, generateResponse, VulType, KB, Type, PluginBase, conf
from helper.basesensitive import sensitive_page_error_message_check


class Z0SCAN(PluginBase):
    name = "sensi-errorpage"
    desc = 'Leak information in Error Page'
    version = "2025.3.2"
    risk = 0
    
    def audit(self):
        if not conf.level == 0:
            headers = self.requests.headers.copy()
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc) + random_str(6)
            r = requests.get(domain, headers=headers)
            messages = sensitive_page_error_message_check(r.text)
            if messages:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.SENSITIVE
                    })
                for m in messages:
                    text = m["text"]
                    _type = m["type"]
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Match tool:{} Match rule:{}".format(_type, text)
                        })
                self.success(result)
