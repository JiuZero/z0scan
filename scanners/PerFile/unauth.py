#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Evi1ran Jan 14, 2021
# JiuZero 2025/3/4

from copy import deepcopy
import difflib
from api import generateResponse, VulType, PLACE, PluginBase, Type, conf

class Z0SCAN(PluginBase):
    name = "unauth"
    desc = 'Unauthorized'
    version = "2025.3.4"
    risk = 2
    
    seqMatcher = difflib.SequenceMatcher(None)
    SIMILAR_MIN = 0.90

    def condition(self):
        if conf.level == 0 or not 2 in conf.risk:
            return False
        for k, v in self.requests.headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                if self.requests.suffix == ".js":
                    return False
                else:
                    return True
        return False
        
    def del_cookie_token(self):
        request_headers = deepcopy(self.requests.headers)
        for k, v in self.requests.headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                del request_headers[k]
                return request_headers, k
                
    def audit(self):
        if not self.condition():
            return
        resp = self.response.text
        headers, k = self.del_cookie_token()
        r = self.req(PLACE.COOKIE, headers)
        if not r:
            return
        min_len = min(len(resp), len(r.text))
        self.seqMatcher = difflib.SequenceMatcher(None, resp[:min_len], r.text[:min_len])
        ratio = round(self.seqMatcher.quick_ratio(), 3)
        if ratio > self.SIMILAR_MIN:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": self.requests.url, 
                "vultype": VulType.UNAUTH, 
                "desc": {
                    "Msg": "Delete {}".format(k)
                    }
                })
            result.step("Request1", {
                "request": r.reqinfo, 
                "response": generateResponse(r), 
                "desc": "Delete {}".format(k)
                })
            self.success(result)
            return