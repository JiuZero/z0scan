#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay
# JiuZero 2025/3/2

from urllib.parse import urlparse
import requests

from api import random_str, generateResponse, VulType, PLACE, Type, PluginBase, conf
from lib.helper.helper_sensitive import sensitive_page_error_message_check


class Z0SCAN(PluginBase):
    name = "ErrorPage"
    desc = 'Leak information in Error Page'
    
    def condition(self):
        if 4 in conf.level:
            return True
        return False
        
    def audit(self):
        if self.condition():
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc) + random_str(6) + ".jsp"
            r = requests.get(domain, headers=headers)
            messages = sensitive_page_error_message_check(r.text)
            if messages:
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, r.url, VulType.SENSITIVE, PLACE.URL)
                for m in messages:
                    text = m["text"]
                    _type = m["type"]
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Match 组件:{} Match 正则:{}".format(_type, text))
                self.success(result)
