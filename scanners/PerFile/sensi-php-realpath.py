#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/4

from lib.core.common import get_middle_text, generateResponse
from api import conf, VulType, Type, PluginBase, Threads


class Z0SCAN(PluginBase):
    name = "sensi-php-realpath"
    desc = 'Php Real Path Finder'
    version = "2025.6.24"
    risk = 0
        
    def audit(self):
        if conf.level == 0 or not 0 in conf.risk or conf.level == 0:
            return
        if not "PHP" in self.fingerprints.programing:
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="sensi-php-realpath")
            z0thread.submit(self.process, iterdatas)
                    
    def process(self, _):
        k, v, position = _
        _k = k + "[]"
        payload = self.insertPayload({
            "key": k, 
            "value": v, 
            "position": position,
            })
        payload[_k] = payload.pop(k)
        r = self.req(position, payload)
        if "Warning" in r.text and "array given in " in r.text:
            path = get_middle_text(r.text, 'array given in ', ' on line')
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": self.requests.url, 
                "vultype": VulType.SENSITIVE, 
                "show": {
                    "Position": position, 
                    "Msg": "{}".format(path), 
                    "Param": _k
                    }
                })
            result.step("Request1", {
                "request": r.reqinfo, 
                "response": generateResponse(r), 
                "desc": "{}".format(path)
                })
            self.success(result)
            return
