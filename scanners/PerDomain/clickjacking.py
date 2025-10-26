#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/15

from api import VulType, Type, PluginBase, conf, KB
import re

class Z0SCAN(PluginBase):
    name = "clickjacking"
    desc = "Clickjacking Vulnerability Scanner"
    version = "2024.6.15"
    risk = -1

    def audit(self):
        if not self.risk in conf.risk or not hasattr(self.response, 'headers'):
            return
        headers_lower = {k.lower(): v for k, v in self.response.headers.items()}
        protection_rules = {
            'x-frame-options': [
                r'deny', #完全禁止嵌入
                r'sameorigin', #仅允许同源嵌入
                r'allow-from', #限制域名嵌入
            ],
            'content-security-policy': [
                r'frame-ancestors\s*[\'"]?\s*(none|self)',
            ]
        }

        vulnerable = True
        for header, patterns in protection_rules.items():
            if header in headers_lower:
                header_value = headers_lower[header].lower()  # 统一小写处理
                for pattern in patterns:
                    if re.search(pattern, header_value):
                        vulnerable = False
                        break

        if vulnerable and self.response.status_code == 200:
            result = self.generate_result()
            result.main({
                "type": Type.ANALYZE,
                "url": self.requests.url,
                "vultype": VulType.OTHER,
            })

            result.step("Request1", {
                "request": self.requests.raw, 
                "response": self.response.raw, 
                "desc": ""
            })
            
            self.success(result)