#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/15

from lib.helper.socketsend import socket_send_withssl, socket_send
from api import generateResponse, VulType, PLACE, HTTPMETHOD, PluginBase, conf, KB, Type

class Z0SCAN(PluginBase):
    name = "webdav-passive"
    desc = 'WebDAV Service Passive Detection'
    version = "2025.5.15"
    risk = 0
    
    def audit(self):
        # 通过检测拓展协议判断为Webdav
        if self.risk in conf.risk:
            keys = ["translate","if","lock-token"]
            for k, v in self.requests.headers.items():
                if k.lower() in keys:
                    result = self.generate_result()
                    result.main({
                        "type": Type.ANALYZE, 
                        "url": self.requests.url, 
                        "vultype": VulType.OTHER
                        })
                    result.step("Request1", {
                        "request": self.requests.raw, 
                        "response": self.response.raw, 
                        "desc": k
                        })
                    self.success(result)