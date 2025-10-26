#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/11

import requests, re
from api import generateResponse, VulType, PLACE, HTTPMETHOD, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = "unauth-webdav-active"
    desc = 'WebDAV authentication bypass vulnerability,'
    version = "2025.5.11"
    risk = 1
        
    def audit(self):
        # 尝试主动未授权
        if not conf.level == 0 and self.risk in conf.risk:
            r = requests.request("PROPFIND", self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port) + "/", headers={"Host": "localhost", "Content-Length": "0"})
            if re.search("<a:href>http://localhost/</a:href>", r.text, re.I):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.UNAUTH
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "<a:href>http://localhost/</a:href>"
                    })
                self.success(result)
                