# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/23

from api import PluginBase, VulType, Type, PLACE, conf, logger, KB, generateResponse
import re

class Z0SCAN(PluginBase):
    name = "sensi-baseline"
    desc = 'Check for version leak on response'
    version = "2025.6.23"
    risk = -1

    def audit(self):
        if -1 in conf.risk:
            self.server_version_leak()
            self.x_powered_by_version_leak()
        
    def server_version_leak(self):
        version = re.search(r"((\d{1,6}\.){1,}\d{1,6})", self.response.headers.get("server", ""))
        if version:
            result = self.generate_result()
            result.main({
                "type": Type.ANALYZE, 
                "url": self.requests.url, 
                "vultype": VulType.SENSITIVE, 
                "show": {
                    "Msg": "Server version: " + self.response.headers["server"]}, 
                })
            result.step("Request1", {
                "request": self.requests.raw, 
                "response": self.response.raw, 
                "desc": self.response.headers["server"],
                })
            self.success(result)
            return

    def x_powered_by_version_leak(self):
        version = re.search(r"((\d{1,6}\.){1,}\d{1,6})", self.response.headers.get("x-powered-by", ""))
        if version:
            result = self.generate_result()
            result.main({
                "type": Type.ANALYZE, 
                "url": self.requests.url, 
                "vultype": VulType.SENSITIVE, 
                "show": {
                    "Msg": "X-Powered-By version: " + self.response.headers["server"]}, 
                    })
            result.step("Request1", {
                "request": self.requests.raw, 
                "response": self.response.raw, 
                "desc": self.response.headers["x-powered-by"]
                })
            self.success(result)
            return
