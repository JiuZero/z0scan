#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/11

import requests, re
from api import generateResponse, VulType, PLACE, HTTPMETHOD, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = "other-webdavPS"
    desc = 'WebDAV authentication bypass vulnerability,'
        
    def condition(self):
        return True
        
    def audit(self):
        if self.condition():
            r = requests.request("PROPFIND", self.requests.netloc, headers={"Host": "localhost", "Content-Length": "0"})
            if re.search("<a:href>http://localhost/</a:href>", r.text, re.I):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "<a:href>http://localhost/</a:href>"
                    })
                self.success(result)
                