#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/26

import requests
from api import VulType, PluginBase, Type, conf, generateResponse, KB


class Z0SCAN(PluginBase):
    name = "trave-list"
    desc = "Directory browsing vulnerability"
    version = "2025.6.26"
    risk = 2

    def audit(self):
        if self.risk in conf.risk and conf.level == 3 and not self.name in KB.disable:
            r = requests.request("GET", self.requests.url.rstrip("/") + "/.listing", allow_redirects=True, verify=False)
            # 判断写得有些草率…后面再改
            if r.status_code == 200:
                result = self.generate_result()
                result.main({
                    "type": Type.ANALYZE, 
                    "url": r.url, 
                    "vultype": VulType.OTHER
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Statuscode is 200."
                    })
                self.success(result)
