#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/7

from api import generateResponse, VulType, Type, PluginBase, conf, logger, KB
import re
import requests
from urllib.parse import urlparse

class Z0SCAN(PluginBase):
    name = "other-hosti"
    desc = "Host Header Injection Detection"
    version = "2025.6.7"
    risk = 1
    
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.name in KB.disable:
            return

        # 修改Host头
        modified_headers = dict(self.requests.headers)
        modified_headers["Host"] = "z0scan.com"
        
        try:
            # 使用requests库发送请求
            if self.requests.scheme == "https":
                verify = False  # 禁用SSL验证（模拟原始代码行为）
            else:
                verify = True
            
            r = requests.request(
                method=self.requests.method,
                url=self.requests.url,
                headers=modified_headers,
                data=self.requests.data,
                verify=verify,
                allow_redirects=False  # 禁止自动重定向以检测注入
            )
        except Exception as e:
            logger.error(f"Request failed: {e}", origin=self.name)
            return
        
        if not r:
            return
        
        success = False
        # 检查Location头
        if "Location" in r.headers and "z0scan.com" in r.headers["Location"]:
            self.report(r, "Redirect in headers")
            success = True
        
        # 检查响应体中的重定向
        if not success:
            try:
                response_body = r.text
            except Exception as e:
                logger.error(f"Failed to read response: {e}", origin=self.name)
                return
            
            patterns = [
                r"<meta[^>]*?url[\s]*?=[\s'\"]*?([^>]*?)['\"]?>",
                r"href[\s]*?=[\s]*?['\"](.*?)['\"]",
                r"window.open\(['\"](.*?)['\"]\)", 
                r"window.navigate\(['\"](.*?)['\"]\)"
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, response_body, re.I)
                for match in matches:
                    if match.strip() and "z0scan" in match:
                        self.report(r, f"Redirect in body, pattern: {pattern}, match: {match}")
                        return
    
    def report(self, response, detail):
        """生成报告（兼容requests.Response对象）"""
        result = self.generate_result()
        result.main({
            "type": Type.REQUEST,
            "url": self.requests.url,
            "vultype": VulType.REDIRECT,
            "show": {
                "Msg": detail
            }
        })
        result.step("Request", {
            "request": self.requests.raw,
            "response": generateResponse(response),
            "desc": detail
        })
        self.success(result)