#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/26

from api import generateResponse, conf, VulType, PLACE, PluginBase, Type, KB

class Z0SCAN(PluginBase):
    name = "cors-passive"
    desc = 'CORS Vulnerability (Passive Analysis)'
    version = "2025.5.26"
    risk = 1
    
    def audit(self):
        if not self.risk in conf.risk:
            return
        headers = self.requests.headers.copy()
        if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
            if "access-control-allow-credentials" in headers and headers["access-control-allow-credentials"].lower() == 'true':
                result = self.generate_result()
                result.main({
                    "type": Type.ANALYZE,
                    "url": self.requests.protocol + "://" + self.requests.hostname + str(self.requests.port),
                    "vultype": VulType.CORS,
                })
                result.step("Request1", {
                    "request": self.requests.raw,
                    "response": self.response.raw,
                    "desc": "access-control-allow-origin: * and access-control-allow-credentials: true"
                })
                self.success(result)