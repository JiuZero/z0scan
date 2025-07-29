#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Reference: https://github.com/shenril/Sitadel
# JiuZero 2025/5/12

import re, random, string
import requests
from api import generateResponse, VulType, PLACE, HTTPMETHOD, PluginBase, conf, KB, Type

class Z0SCAN(PluginBase):
    name = "other-xst"
    desc = 'XST Vulnerability Detection'
    version = "2025.5.12"
    risk = -1
    
    def audit(self):
        if not conf.level == 0 and self.risk in conf.risk and not self.name in KB.disable:
            rand_str = ''.join(random.choices(string.hexdigits, k=4)).lower()
            r = requests.request("TRACE", self.requests.netloc + "/*", allow_redirects=True, verify=False, headers={f"{rand_str}": "{rand_str}"})
            if re.search(f"{rand_str}: *?{rand_str}", r.text, re.I):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.OTHER
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"Find {rand_str}: *?{rand_str} in response."
                    })
                self.success(result)