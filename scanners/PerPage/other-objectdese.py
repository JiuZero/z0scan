#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4

from copy import deepcopy
from api import PluginBase, VulType, isJavaObjectDeserialization, isPHPObjectDeserialization, isPythonObjectDeserialization, Type, PLACE, conf, KB


class Z0SCAN(PluginBase):
    name = "objectdese"
    desc = 'Deserialization Parameter Analysis'
    version = "2025.3.4"
    risk = 3
    
    def _check(self, k, v, position):
        whats = None
        if isJavaObjectDeserialization(v):
            whats = "JavaObjectDeserialization"
        elif isPHPObjectDeserialization(v):
            whats = "PHPObjectDeserialization"
        elif isPythonObjectDeserialization(v):
            whats = "PythonObjectDeserialization"
        if whats:
            result = self.generate_result()
            result.main({
                "type": Type.ANALYZE, 
                "url": self.requests.url, 
                "vultype": VulType.OTHER, 
                "show": {
                    "Position": position, 
                    "Param": k, 
                    "Payload": v, 
                    "Msg": "{}".format(whats)
                    }
                })
            result.step("Request1", {
                "request": self.requests.raw, 
                "response": self.response.raw, 
                "desc": "{} is the deserialization of {} as result".format(k, whats)
                })
            self.success(result)

    def audit(self):
        if not self.risk in conf.risk or conf.level == 0:
            return
        params = deepcopy(self.requests.params)
        data = deepcopy(self.requests.data)
        cookies = deepcopy(self.requests.cookies)
        if params:
            for k, v in params.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, PLACE.PARAM)
        if data:
            for k, v in data.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, PLACE.NORMAL_DATA)
        if cookies:
            for k, v in cookies.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, PLACE.COOKIE)
