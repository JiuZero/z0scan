#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/6/16

import random
import re
from api import VulType, md5, generateResponse, conf, PluginBase, Type, logger, Threads, PLACE, KB
from lib.helper.helper_sensitive import sensitive_page_error_message_check


class Z0SCAN(PluginBase):
    name = "codei-php"
    desc = 'PHP Code Injection'
    version = "2025.6.16"
    risk = 3
            
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.fingerprints.waf or self.name in KB.disable:
            return
        if not "PHP" in self.fingerprints.programing:
            randint = random.randint(10120, 10240)
            verify_result = md5(str(randint).encode())
            _payloads = [
                r"print(md5({}));".format(randint),
                r";print(md5({}));".format(randint),
                r"';print(md5({}));$a='".format(randint),
                r"\";print(md5({}));$a=\"".format(randint),
                r"${{@print(md5({}))}}".format(randint),
                r"${{@print(md5({}))}}\\".format(randint),
                r"'.print(md5({})).'".format(randint)
            ]

            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="codei-php")
            z0thread.submit(self.process, iterdatas, _payloads, verify_result)

    def process(self, _, _payloads, verify_result):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        regx = r'Parse error: syntax error,.*?\sin\s'
        errors = None
        errors_raw = ()
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k, 
                "position": position, 
                "payload": _payload
                })
            r = self.req(position, payload)
            if not r:
                continue
            html1 = r.text
            if verify_result in html1:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.CODE_INNJECTION, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": _payload
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Receive {}".format(verify_result)
                    })
                self.success(result)
                break
            if re.search(regx, html1, re.I | re.S | re.M):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.CODE_INNJECTION, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": _payload
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Receive Return {}, maybe is the error because of payload".format(regx)
                    })
                self.success(result)
                break
            if not errors:
                errors = sensitive_page_error_message_check(html1)
                if errors:
                    errors_raw = (k, v)

        if errors:
            result = self.generate_result()
            key, value = errors_raw
            result.main({
                "type": Type.REQUEST, 
                "url": self.requests.url, 
                "vultype": VulType.SENSITIVE, 
                "show": {
                    "Position": f"{position} >> {k}", 
                    "Msg": "Error message detected in the response page"
                    }
                })
            for m in errors:
                text = m["text"]
                _type = m["type"]
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Match Tools:{} Match:{}".format(_type, text)
                    })
            self.success(result)
