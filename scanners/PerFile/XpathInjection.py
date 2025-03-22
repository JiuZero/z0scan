#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/18

import re
import random
import string
from api import generateResponse, VulType, PLACE, Type, PluginBase, KB, conf
from concurrent.futures import ThreadPoolExecutor, as_completed

class Z0SCAN(PluginBase):
    name = "XpathInjection"
    desc = 'XPath Injection'

    def condition(self):
        if not KB["WAFSTATE"] and 4 in conf.level:
            return True
        return False
    
    def _dynamic_payloads(self):
        rand_num = random.randint(1000, 9999)
        
        return [
            # 基础闭合测试
            "'", "\"", "')", "')", "<!--",
            # 表达式测试
            f"][{rand_num}]", f" or {rand_num}={rand_num}",
            f"|//*[contains(.,{rand_num})]", 
            # 函数测试
            f"count(//*[position()={rand_num}])",
            # 错误诱导
            f"convert({rand_num}, 'invalid_type')",
            # 特殊字符组合
            "]]>", "*/*", "]["
        ]

    def _error_patterns(self):
        return {
            'exact': [
                'MS.Internal.Xml.',
                'org.apache.xpath.XPath',
                'Expression must evaluate to a node-set',
                'System.Xml.XPath.XPathException'
            ],
            'regex': [
                r"XPathException: .*?'(?P<detail>.+?)'",  # 捕获错误详情
                r"Line \d+: Invalid expression",
                r"at (org\.apache\.xpath|javax\.xml\.xpath)",
                r"Error code: 0x[0-9a-fA-F]+ \(XPath\)"
            ]
        }

    def _detect_errors(self, response_text):
        if not response_text:
            return False, None

        # 精确匹配优先
        for pattern in self._error_patterns()['exact']:
            if pattern in response_text:
                return True, f"Exact Match {pattern}"

        # 正则匹配
        for regex in self._error_patterns()['regex']:
            match = re.search(regex, response_text, re.I)
            if match:
                detail = match.groupdict().get('detail', match.group(0))
                return True, f"Regex Match {detail}"

        return False, None

    def audit(self):
        if not self.condition():
            return
        iterdatas = self.generateItemdatas()
        with ThreadPoolExecutor(max_workers=None) as executor:
            futures = [
                executor.submit(self.process, _) for _ in iterdatas
            ]
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise
                
    def process(self, _):
        k, v, position = _
        _payloads = self._dynamic_payloads()
        for _payload in _payloads:
            payload = self.insertPayload(
                k,
                v,
                position, 
                _payload
            )
            r = self.req(position, payload)
            if not r or r.status_code >= 500:
                continue
            is_vuln, error_info = self._detect_errors(r.text)
            if not is_vuln:
                continue
            result = self.new_result()
            result.init_info(
                Type.REQUEST,
                self.requests.hostname,
                self.requests.url,
                VulType.INJECTION,
                position,
                msg=f"Match Error {error_info}",
                key=k,
                value=payload
            )
            result.add_detail(
                "Request",
                r.reqinfo,
                generateResponse(r),
                f"Match Error {error_info}"
            )
            self.success(result)
            return True