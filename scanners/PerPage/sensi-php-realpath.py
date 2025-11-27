#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/4

from lib.core.common import get_middle_text, generateResponse
from api import conf, VulType, Type, PluginBase, Threads, KB, PLACE
import re


class Z0SCAN(PluginBase):
    name = "sensi-php-realpath"
    desc = 'PHP Real Path Discovery'
    version = "2025.6.24"
    risk = 0
        
    def audit(self):
        if conf.level == 0:
            return
        if not "PHP" in self.fingerprints.finger:
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="sensi-php-realpath")
            z0thread.submit(self.process, iterdatas)
                    
    def process(self, _):
        k, v, position = _
        _k = k + "[]"
        payload = None
        if position == PLACE.URL:
            pattern = r'(/{}(?:[-_/]|\.))([^?#&]*)'.format(re.escape(k))
            def replacement(match):
                separator = match.group(1)
                separator = separator.replace(str(k), str(_k))
                original_value = match.group(2)
                return '{}{}{}'.format(separator, original_value, v)
            url = re.sub(pattern, replacement, self.requests.url, flags=re.I)
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position,
            })
            
        else:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position,
            })
        if isinstance(payload, dict):
            if _k in payload:
                # 避免重复键名
                return
            if k in payload:
                payload[_k] = payload.pop(k)
        else:
            return
            
        r = self.req(position, payload)
        if r and "Warning" in r.text and "array given in " in r.text:
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