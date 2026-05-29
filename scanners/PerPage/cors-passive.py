#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

from api import generateResponse, conf, VulType, PLACE, PluginBase, Type, KB

class Z0SCAN(PluginBase):
    name = "cors-passive"
    desc = 'CORS Vulnerability (Passive Analysis)'
    version = "2025.5.26"
    risk = 1
    
    def audit(self):
        headers = self.requests.headers.copy()
        for k, v in headers.items():
            if k.lower() == "access-control-allow-origin" and (headers[k] == "*" or headers[k] == "https://www.test.com"):
                for k, v in headers.items():
                    if k.lower() == "access-control-allow-credentials" and headers[k].lower() == 'true':
                        result = self.generate_result()
                        result.main({
                            "type": Type.ANALYZE,
                            "url": self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port),
                            "vultype": VulType.CORS,
                        })
                        result.step("Request0", {
                            "request": self.requests.raw,
                            "response": self.response.raw,
                            "desc": "access-control-allow-origin: * and access-control-allow-credentials: true"
                        })
                        self.success(result)