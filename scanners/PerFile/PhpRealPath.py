#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/4

import copy
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.core.common import get_middle_text, generateResponse
from api import conf, WEB_PLATFORM, HTTPMETHOD, PLACE, VulType, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "PhpRealPath"
    desc = 'Php Real Path Finder'
    
    def condition(self):
        for k, v in self.response.programing.items():
            if k == WEB_PLATFORM.PHP and 4 in conf.level:
                return True
        return False
        
    def audit(self):
        if self.condition():
            headers = self.requests.headers
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
        _k = k + "[]"
        payload = self.insertPayload(_k, v, position, "")
        r = self.req(position, payload)
        if "Warning" in r.text and "array given in " in r.text:
            path = get_middle_text(r.text, 'array given in ', ' on line')
            result = self.new_result()
            result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SENSITIVE, position, msg="PATH Sensitive {p}".format(p=path), param=_k)
            result.add_detail("Request", r.reqinfo, generateResponse(r))
            self.success(result)
            return True
