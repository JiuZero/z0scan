#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/1

import requests
from api import VulType, Type, PluginBase, KB, generateResponse, conf

class Z0SCAN(PluginBase):
    name = "sensi-iis-shortname"
    desc = 'IIS File ShortName'
    version = "2025.3.1"
    risk = 0
    
    def audit(self):
        if not "IIS" in self.fingerprints.webserver and self.risk in conf.risk and conf.level != 0:
            existed_path = '/*~1*/a.aspx'
            not_existed_path = '/JiuZer0~1*/a.aspx'
            r1 = requests.get(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port) + existed_path)
            status_1 = r1.status_code
            r2 = requests.get(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port) + not_existed_path)
            status_2 = r2.status_code
            if status_1 == 404 and status_2 != 404:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r1.url, 
                    "vultype": VulType.SENSITIVE
                    })
                result.step("Request1", {
                    "request": r1.reqinfo, 
                    "response": generateResponse(r1), 
                    "desc": "Request1 Status Code is 404"
                    })
                result.step("Request2", {
                    "request": r2.reqinfo, 
                    "response": generateResponse(r2), 
                    "desc": "But Request2 isn't 404"
                    })
                self.success(result)
                return True
            r1 = requests.options(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port) + existed_path)
            status_1 = r1.status_code
            r2 = requests.options(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port) + not_existed_path)
            status_2 = r2.status_code
            if status_1 == 404 and status_2 != 404:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r1.url, 
                    "vultype": VulType.OTHER
                    })
                result.step("Request1", {
                    "request": r1.reqinfo, 
                    "response": generateResponse(r1), 
                    "desc": "Request1 Status Code is 404"
                    })
                result.step("Request2", {
                    "request": r2.reqinfo, 
                    "response": generateResponse(r2), 
                    "desc": "But Request2 isn't 404"
                    })
                self.success(result)
                return True