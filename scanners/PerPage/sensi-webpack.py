#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/22
# JiuZero 2025/5/8

import requests
from api import generateResponse, random_num, PLACE, VulType, Type, PluginBase, conf, KB


class Z0SCAN(PluginBase):
    name = 'webpack'
    desc = "Webpack Source Code Leak"
    version = "2025.5.8"
    risk = 1

    def audit(self):
        if conf.level == 0:
            return False
        if self.requests.suffix.lower() == '.js':
            new_url = self.requests.url + ".map"
            req = requests.get(new_url, headers=self.requests.headers)
            if req.status_code == 200 and 'webpack:///' in req.text:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": req.url, 
                    "vultype": VulType.SENSITIVE
                    })
                result.step("Request1", {
                    "request": req.reqinfo, 
                    "response": generateResponse(req), 
                    "desc": "webpack:/// in response's text"
                    })
                self.success(result)
