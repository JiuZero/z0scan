#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 2025/5/26 JiuZero

from api import VulType, Type, KB, PluginBase, generateResponse, conf
from viewstate import ViewState
import re

class Z0SCAN(PluginBase):
    name = "sensi-viewstate"
    desc = "Unencrypted VIEWSTATE Discovery"
    version = "2025.5.26"
    risk = 0
    
    def find_viewstate(self):
        patterns = [
            re.compile(r'<input[^>]+__VIEWSTATE["\' ][^>]*value=["\']([^"\']+)', re.I),
            re.compile(r'<input[^>]+value=["\']([^"\']+)["\' ][^>]+__VIEWSTATE', re.I),
            re.compile(r'__VIEWSTATE=([A-Za-z0-9+/=]+)')
        ]
        found = []
        # 从响应体中匹配
        for pattern in patterns:
            found.extend(pattern.findall(self.response.text))
        # 从POST参数中获取
        if self.requests.data:
            found.extend(v for k, v in self.requests.data.items() if k.lower() == "__viewstate")
        return list(set(found))
    
    def audit(self):
        if not self.risk in conf.risk or not "ASP" in self.fingerprints.programing:
            return
        viewstate_list = self.find_viewstate()
        
        for vs_value in viewstate_list:
            try:
                decoded = ViewState(vs_value).decode()
                if decoded:
                    result = self.generate_result()
                    result.main({
                        "type": Type.ANALYZE, 
                        "url": self.requests.url, 
                        "vultype": VulType.SENSITIVE, 
                        "show": {
                            "Msg": "ViewState does not have MAC validation enabled. Try for dese?", 
                            "Decode": str(decoded)[:50] + "..."
                            }
                        })
                    result.step("Request1", {
                        "request": self.requests.raw, 
                        "response": self.response.raw, 
                        "desc": f"Length: {len(str(decoded))}"
                        })
                    self.success(result)
                    return
            except Exception as e:
                pass