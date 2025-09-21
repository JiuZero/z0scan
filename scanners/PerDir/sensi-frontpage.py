#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/26

import requests
from api import generateResponse, VulType, PluginBase, conf, KB, Type

class Z0SCAN(PluginBase):
    name = "sensi-frontpage"
    desc = "FrontPage configuration information discloure"
    risk = 1
    version = "2025.6.26"

    def audit(self):
        if self.requests.url.count("/") > int(conf.max_dir) + 2:
            return
        if conf.level == 0:
            return
        url = self.requests.url.rstrip("/") + "/_vti_inf.html"
        r = requests.get(url)
        if r is not None and len(r.content) == 247:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": url, 
                "vultype": VulType.SENSITIVE, 
                })
            result.step("Request1", {
                "request": r.reqinfo, 
                "response": generateResponse(r), 
                "desc": f"Content length is 247."
                })
            self.success(result)
