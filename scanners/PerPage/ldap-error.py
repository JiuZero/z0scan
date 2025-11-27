#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import re
import random
from api import generateResponse, VulType, Type, PluginBase, KB, conf, Threads

class Z0SCAN(PluginBase):
    name = "ldap-error"
    desc = 'Error-based LDAP Injection'
    version = "2025.10.16"
    risk = 2

    def _detect_errors(self, response_text):
        error_patterns = [
            "supplied argument is not a valid ldap",
            "javax.naming.NameNotFoundException",
            "javax.naming.directory.InvalidSearchFilterException",
            "Invalid DN syntax",
            "LDAPException|com.sun.jndi.ldap",
            "Search: Bad search filter",
            "Protocol error occurred",
            "Size limit has exceeded",
            "The alias is invalid",
            "Module Products.LDAPMultiPlugins",
            "Object does not exist",
            "The syntax is invalid",
            "A constraint violation occurred",
            "An inappropriate matching occurred",
            "Unknown error occurred",
            "The search filter is incorrect",
            "Local error occurred",
            "The search filter is invalid",
            "The search filter cannot be recognized",
            "IPWorksASP.LDAP",
        ]
        if not response_text:
            return False, None
        # 正则匹配
        for regex in error_patterns:
            match = re.search(regex, response_text, re.I)
            if match:
                detail = match.groupdict().get('detail', match.group(0))
                return True, f"Regex Match {detail}"
        return False, None

    def audit(self):
        if conf.level == 0 or self.fingerprints.waf:
            return
        iterdatas = self.generateItemdatas()
        z0thread = Threads(name=self.name)
        z0thread.submit(self.process, iterdatas)
                
    def process(self, _):
        k, v, position = _
        rand_num = random.randint(1000, 9999)
        _payloads = [
            "\21", 
            "*()|&'", 
            "@*", 
        ]
        if conf.level == 3:
            _payloads += [
                "(*)*)", 
                "*)*", 
                "*/*", 
                "//*", 
            ]
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": _payload
                })
            r = self.req(position, payload)
            if not r.text:
                continue
            is_vuln, error_info = self._detect_errors(r.text)
            if is_vuln:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.OTHER, 
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Payload": payload
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"{error_info}"
                    })
                self.success(result)
                return