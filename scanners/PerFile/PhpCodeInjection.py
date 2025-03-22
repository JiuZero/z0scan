#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/3/4

import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from api import VulType, md5, generateResponse, conf, KB, WEB_PLATFORM, PluginBase, Type
from lib.helper.helper_sensitive import sensitive_page_error_message_check


class Z0SCAN(PluginBase):
    name = "PhpCodeInjection"
    desc = 'PHP Code Injection'

    def condition(self):
        for k, v in self.response.programing.items():
            if k == WEB_PLATFORM.PHP and 4 in conf.level and not KB["WAFSTATE"]:
                return True
            return False
            
    def audit(self):
        if self.condition():
            regx = 'Parse error: syntax error,.*?\sin\s'
            randint = random.randint(5120, 10240)
            verify_result = md5(str(randint).encode())
            _payloads = [
                "print(md5({}));".format(randint),
                ";print(md5({}));".format(randint),
                "';print(md5({}));$a='".format(randint),
                "\";print(md5({}));$a=\"".format(randint),
                "${{@print(md5({}))}}".format(randint),
                "${{@print(md5({}))}}\\".format(randint),
                "'.print(md5({})).'".format(randint)
            ]

            iterdatas = self.generateItemdatas()
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.process, _, _payloads, verify_result, regx) for _ in iterdatas
                ]
                try:
                    for future in as_completed(futures):
                        future.result()
                except KeyboardInterrupt:
                    executor.shutdown(False)

    def process(self, _, position, _payloads, verify_result, regx):
        k, v, position = _
        errors = None
        errors_raw = ()
        for _payload in _payloads:
            payload = self.insertPayload(k, "", position, _payload)
            r = self.req(k, v, position, payload)
            if not r:
                continue
            html1 = r.text
            if verify_result in html1:
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, r.url, VulType.CMD_INNJECTION, position, param=k, payload=payload)
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Receive {}".format(verify_result))
                self.success(result)
                break
            if re.search(regx, html1, re.I | re.S | re.M):
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, r.url, VulType.CMD_INNJECTION, position, param=k, payload=payload)
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Receive Return {}, maybe is the error because of payload".format(regx))
                self.success(result)
                break
            if not errors:
                errors = sensitive_page_error_message_check(html1)
                if errors:
                    errors_raw = (k, v)

        if errors:
            result = self.new_result()
            key, value = errors_raw
            result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SENSITIVE, position, param=key, payload=value)
            for m in errors:
                text = m["text"]
                _type = m["type"]
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Match Tools:{} Match:{}".format(_type, text))
            self.success(result)
