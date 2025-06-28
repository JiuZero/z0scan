#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/26

import re, requests
from api import VulType, PLACE, PluginBase, Type, conf, generateResponse


class Z0SCAN(PluginBase):
    name = "trave-list"
    desc = "Directory browsing vulnerability"
    version = "2025.6.26"
    risk = 2

    def audit(self):
        if 2 in conf.risk and conf.level == 3:
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
