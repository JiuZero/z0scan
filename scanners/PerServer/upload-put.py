#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/7

from api import VulType, Type, PLACE, PluginBase, generateResponse, random_str, random_num, conf, KB
import requests

class Z0SCAN(PluginBase):
    name = "upload-put"
    desc = "Detect the vulnerability of uploading arbitrary files by PUT method"
    version = "2025.5.7"
    risk = 3
    
    def _put_upload(self):
        filename = f"{random_str(8)}_{random_num(6)}.txt"
        content = f"{random_str(12)}"
        target_url = f"{self.requests.hostname}/{filename}"
        try:
            r1 = requests.put(target_url, data=content, headers=self.requests.headers, verify=False)
            if r1.status_code in [200, 201, 204]:
                r2 = requests.get(target_url, headers={"Range": "bytes=0-50"})
                if r2.status_code == 200 and content in r2.text:
                    r = r1, r2
                    return r
                if r2.status_code == 206 and content in r2.text:
                    return r
        except Exception as e:
            pass
        return None
    
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.name in KB.disable:
            return
        if r := self._put_upload():
            r1, r2 = r
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": r1.url, 
                "vultype": VulType.FILEUPLOAD
                })
            result.step("Request1", {
                "request": r1.reqinfo, 
                "response": generateResponse(r1), 
                "desc": f"Target URL: {r1.url}"
                })
            result.step("Request2", {
                "request": r2.reqinfo, 
                "response": generateResponse(r2), 
                "desc": "Content matches verification string"
                })
            self.success(result)
            return