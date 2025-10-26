#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from api import generateResponse, VulType, Type, PluginBase, conf, Threads
import time

class Z0SCAN(PluginBase):
    name = "redos"
    desc = "Regular Expression Denial of Service (ReDoS) Vulnerability Scanner"
    version = "2025.9.2"
    risk = -1

    def audit(self):
        if (conf.level != 0) and self.risk in conf.risk:
            _redos_payloads = [
                "a" * 500 + "aaaaaab",
                "x" * 300 + "xxxxxxy",
                "<" * 400 + "<<<<<<!",
                "(" * 350 + "((((((",
                "[a-z]*" * 200 + "z",
                "123-" * 250 + "456"
            ]
            if conf.level == 3:
                _redos_payloads += [
                    "{" * 400 + "}}}}}}",
                    "\"" * 300 + "\"\"\"\"\"",
                    "\\" * 250 + "\\\\\\\\",
                    "[" * 350 + "]]]]]]"
                ]

            iterdatas = self.generateItemdatas()
            if not iterdatas:
                return

            z0thread = Threads(name=self.name)
            z0thread.submit(self.process, iterdatas, _redos_payloads)

    def process(self, _, _payloads):
        k, v, position = _
        base_time = 0.1
        for _payload in _payloads:
            modified_data = self.insertPayload({
                "key": k,
                "position": position,
                "payload": _payload
            })

            start_time = time.time()
            r = self.req(position, modified_data)
            end_time = time.time()
            req_duration = end_time - start_time

            if not r:
                continue

            redos_flag = req_duration > base_time * 8
            if redos_flag:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST,
                    "url": self.requests.url,
                    "vultype": VulType.OTHER,
                    "show": {
                        "Position": f"{position} > {k}",
                        "ReDoS Payload": f"{_payload[:50]}..." if len(_payload) > 50 else _payload,
                        "Response Time": f"{req_duration:.2f}s",
                        "Msg": "Regular Expression Denial of Service (ReDoS) Vulnerability"
                    }
                })
                result.step("Request-ReDoS", {
                    "request": r.reqinfo,
                    "response": generateResponse(r),
                    "desc": f"ReDoS payload caused request delay ({req_duration:.2f}s > {base_time*8:.2f}s) (risk: MEDIUM)"
                })
                self.success(result)
                return True
