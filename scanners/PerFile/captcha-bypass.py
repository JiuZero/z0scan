#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/14

import re
from api import VulType, Type, PluginBase, conf, logger, generateResponse, KB

class Z0SCAN(PluginBase):
    name = "captcha-bypass"
    desc = "Frontend Captcha Bypass Detection"
    version = "2024.6.1"
    risk = 0
        
    def audit(self):
        if not self.risk in conf.risk or self.name in KB.disable:
            return

        # 基于前端的验证码绕过(生成代码在前端)
        raw_response = self.response.raw
        if raw_response:
            captcha_pattern = re.compile(
                r'(var|let|const)\s+(code|vcode|verifyCode|captcha)\s*?;?\s*?(\/\/.*?验证码)?'
                r'[\s\S]{0,50}?function\s+?(create|generate|make|init)(Code|VCode|VerifyCode|Captcha)'
                r'[\s\S]{0,200}?=\s*?["\'`]?[\s\S]{0,50}?codeLength\s*?=',
                re.IGNORECASE
            )
            if captcha_pattern.search(raw_response):
                result = self.generate_result()
                result.main({
                    "type": Type.ANALYZE,
                    "url": self.requests.url,
                    "vultype": VulType.OTHER,
                    "show": {
                        "Msg": "Captcha value/function exposed in source code",
                    }
                })
                self.success(result)
                return

        # 主动检测部分
        if conf.level == 0:
            return
        # 必须在用户输入正确的验证码，并发起请求后检测
        captcha_pattern = re.compile(
            r"验证码错误|验证码不正确|captcha\s*error|invalid\s*code|"
            r"验证码已过期|请重新输入验证码|code\s*error|验证码无效",
            re.IGNORECASE
        )
        iterdatas = self.generateItemdatas()
        for k, v, position in iterdatas:
            captcha_params = ["captcha", "code", "vcode"]
            if k.lower() in captcha_params:
                # 验证码重用
                original_payload = self.insertPayload({
                    "key": k,
                    "value": v,
                    "position": position,
                    "payload": ""
                })
                
                r = self.req(position, original_payload)
                if not r or r.status_code != 200:
                    continue
                if not captcha_pattern.search(r.text):
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST,
                        "url": self.requests.url,
                        "vultype": VulType.OTHER,
                        "show": {
                            "Msg": "Captcha reuse bypass successful",
                        }
                    })
                    result.step("Request1", {
                        "request": self.requests.raw,
                        "response": self.response.raw,
                        "desc": "Captcha reuse bypass successful"
                    })
                    result.step("Request2", {
                        "request": r.reqinfo,
                        "response": generateResponse(r),
                        "desc": "Captcha reuse bypass successful"
                    })
                    self.success(result)
                    return

                # 空验证码
                empty_payload = self.insertPayload({
                    "key": k,
                    "value": "",
                    "position": position,
                    "payload": ""
                })
                r = self.req(position, empty_payload)
                if r and r.status_code == 200:
                    if not captcha_pattern.search(r.text):
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST,
                            "url": self.requests.url,
                            "vultype": VulType.OTHER,
                            "show": {
                                "Evidence": "Empty captcha bypass successful"
                            }
                        })
                        result.step("Request1", {
                            "request": self.requests.raw,
                            "response": self.response.raw,
                            "desc": "Empty captcha bypass successful"
                        })
                        result.step("Request2", {
                                "request": r.reqinfo,
                                "response": generateResponse(r),
                                "desc": "Empty captcha bypass successful"
                            })
                        self.success(result)
                        return