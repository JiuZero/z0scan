#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4

import re

from config.others.JsSensi import rules
from api import VulType, PLACE, Type, PluginBase, conf


class Z0SCAN(PluginBase):
    name = "sensi-js"
    desc = 'Js Sensitive Finder'
    version = "2025.3.4"
    risk = 0
        
    def audit(self):
        if not (self.requests.suffix == ".js" or 0 in conf.risk):
            return
        for name, _ in rules.items():
            texts = re.findall(_, self.response.text, re.M | re.I)
            issuc = False
            if texts:
                for text in set(texts):
                    ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                    is_continue = True

                    for i in ignores:
                        if i in text:
                            is_continue = False
                            break
                    if not is_continue:
                        continue

                    result = self.generate_result()
                    result.main({
                        "type": Type.ANALYZE,
                        "url": self.requests.url, 
                        "vultype": VulType.SENSITIVE, 
                        "show": {
                            "Msg": "{}".format(text)
                            }
                        })
                    result.step("Request1", {
                        "request": self.requests.raw, 
                        "response": self.response.raw, 
                        "desc": "From Regx {} Find Sensitive Info {}".format(_, text)
                        })
                    self.success(result)
                    issuc = True
                    break
            if issuc:
                break
