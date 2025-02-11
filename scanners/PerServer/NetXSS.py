#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : w8ay

from urllib.parse import urlparse

import requests
from lib.core.data import conf, KB
from lib.core.common import random_str, generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class Z0SCAN(PluginBase):
    name = '.NET通杀XSS'

    def audit(self):
        if conf.level == 4 and not KB["WafState"]:
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
                    result.init_info(self.requests.url, ".NET通杀XSS", VulType.XSS)
                    result.add_detail("Payload回显", req.reqinfo, generateResponse(req),
                                    "Payload:{}回显在页面".format(payload), "", "", PLACE.GET)
                    result.add_detail("Payload回显", req2.reqinfo, generateResponse(req2),
                                    "Payload:{}回显在页面".format(payload), "", "", PLACE.GET)
                    self.success(result)
