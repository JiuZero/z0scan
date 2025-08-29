#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/28

import re, requests
import copy, random, string
from urllib.parse import quote
from api import generateResponse, VulType, KB, Type, PluginBase, conf, Threads

class Z0SCAN(PluginBase):
    name = "crlf_3"
    desc = 'CRLF Line Injection Vulnerability (Domain-based)'
    version = "2025.6.28"
    risk = 2

    def _check_response(self, resp, test_header):
        header_name_lower = test_header['header_name'].lower()
        for resp_header_name in resp.headers:
            if resp_header_name.lower() == header_name_lower:
                header_value = resp.headers[resp_header_name]
                if test_header['header_value'] in header_value:
                    return True, "headers"
        header_name_escaped = re.escape(test_header['header_name'])
        header_value_escaped = re.escape(test_header['header_value'])
        # 匹配头格式: X-Test: value (允许前后空白)
        header_pattern = re.compile(
            rf"^{header_name_escaped}\s*:\s*{header_value_escaped}\s*$",
            re.I | re.M
        )
        # 匹配Set-Cookie格式: Set-Cookie: X-Test=value
        set_cookie_pattern = re.compile(
            rf"^Set-Cookie\s*:\s*{header_name_escaped}={header_value_escaped}(?:;|$)",
            re.I | re.M
        )
        if (header_pattern.search(resp.text) or 
            set_cookie_pattern.search(resp.text)):
            return True, "body"
        return False, None
        

    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.fingerprints.waf:
            return
        _payloads = [
            # 基础换行组合
            f"\\r\\n\\t",
            "%0a%0a", 
        ]
        if conf.level >= 2:
            _payloads += [
                '%250a', 
                "čĊ", # Node.js风格  
                '%3f%23%0d%0a%09', 
                '%25%30%61', 
            ]
        if conf.level == 3:
            _payloads += [
                "%0d%0a", 
                '%3f', 
                "嘊嘍",    # Twitter风格
                '%u000d%u000a', # UNICODE
                '%25250a', # 三次URL编码
            ]
        rand_str1 = ''.join(random.choices(string.hexdigits, k=6)).lower()
        rand_str2 = ''.join(random.choices(string.hexdigits, k=4)).lower()
        starting_strings = ["", f"{rand_str2}", f"?{rand_str2}=", "#", "__session_start__/"]
        test_header = {
            'header_name': f"X-{rand_str1}",
            'header_value': f"{rand_str1}"
        }
        z0thread = Threads(name="crlf_3")
        z0thread.submit(self.process, starting_strings, _payloads, test_header)
        
    def process(self, starting_string, _payloads, test_header):
        for _payload in _payloads:
            _payload = f"/{starting_string}{_payload}{test_header['header_name']}: {test_header['header_value']}"
            r = requests.get(self.requests.netloc + _payload)
            is_vuln, location = self._check_response(r, test_header)
            if not is_vuln:
                continue
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST,
                "url": self.requests.url,
                "vultype": VulType.CRLF,
                "show": {
                    "Payload": _payload
                }
            })
            result.step("Request1", {
                "request": r.reqinfo,
                "response": generateResponse(r),
                "desc": f"Find {test_header['header_name']} in {location}"
            })
            self.success(result)
            return