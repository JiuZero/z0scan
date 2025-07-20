#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/21

from lib.helper.helper_retirejs import main_scanner, js_extractor
from api import VulType, Type, PLACE, PluginBase, generateResponse, conf, KB


class Z0SCAN(PluginBase):
    name = 'sensi-retirejs'
    desc = 'Detects outdated JavaScript libraries with known vulnerabilities'
    version = "2025.6.21"
    risk = -1

    def audit(self):
        if self.risk in conf.risk and not self.name in KB.disable:
            js_links = js_extractor(self.response.raw)
            ret = main_scanner(self.requests.url, self.response.raw)
            if ret:
                self._result(self.requests.url, ret)
            for link in js_links:
                ret2 = main_scanner(link, '')
                if ret2:
                    self._result(link, ret2)
                    
    def _result(self, link, ret):
        result = self.generate_result()
        result.main({
            "type": Type.ANALYZE, 
            "url": link, 
            "vultype": VulType.SENSITIVE, 
            })
        result.step("Request1", {
            "request": self.requests.raw, 
            "response": self.response.raw, 
            "desc": f"The page includes JavaScript libraries with known vulnerabilities"
            })
        self.success(result)
