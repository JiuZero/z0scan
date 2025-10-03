#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/20

import requests
from urllib.parse import quote
from lib.core.settings import acceptedExt
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB, isjson

class Z0SCAN(PluginBase):
    name = "other-json-error"
    desc = 'other-json-error'
    version = "2025.8.20"
    risk = 2
    
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk:
            return
        if self.requests.suffix in acceptedExt:
            test_args = []
            if self.requests.post_hint == POST_HINT.JSON:
                payload = self.requests.body.replace(b"}", b"", 1)
                r = requests.get(self.requests.url, params=self.requests.params, data=payload, headers=self.requests.headers)
                if not r:
                    return
                keys = ["jackson", "fastjson", "autotype"]
                for key in keys:
                    if key.encode() in r.content.lower():
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.OTHER, 
                            "show": {
                                "Position": f"body", 
                                "Payload": payload, 
                                "Msg": f"Found {key} in response.",
                                }
                            })
                        result.step("Request1", {
                            "position": position,
                            "request": r.reqinfo, 
                            "response": generateResponse(r), 
                            "desc": f"Found {key} in response. Payload: {payload}"
                            })
                        self.success(result)
                        break
            elif self.requests.params or self.requests.post_hint == POST_HINT.NORMAL or self.requests.post_hint == POST_HINT.ARRAY_LIKE:
                iterdatas = self.generateItemdatas()
                for _ in iterdatas:
                    k, v, position = _
                    # 判断参数值是否为json格式
                    if isjson(v):
                        test_args.append(_)     
                z0thread = Threads(name="other-json-error")
                z0thread.submit(self.process, test_args)
                
    def process(self, _):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        payload = v.replace("}", "", 1)
        payload = self.insertPayload({
            "key": k, 
            "payload": payload, 
            "position": position, 
            })
        r = self.req(position, payload)
        if not r:
            return
        keys = ["jackson", "fastjson", "autotype"]
        for key in keys:
            if key.encode() in r.content.lower():
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.OTHER, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": payload, 
                        "Msg": f"Found {key} in response.",
                        }
                    })
                result.step("Request1", {
                    "position": position,
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"Found {key} in response. Payload: {payload}"
                    })
                self.success(result)
                break

