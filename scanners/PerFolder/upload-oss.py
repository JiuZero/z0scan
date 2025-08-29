#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/31

from api import VulType, Type, KB, PluginBase, generateResponse, random_str, random_num, conf
import requests

class Z0SCAN(PluginBase):
    name = "upload-oss"
    desc = "Detect the vulnerability of uploading arbitrary files to OSS"
    version = "2025.5.31"
    risk = 3
    
    def _test_upload(self, method="PUT"):
        url = self.requests.url.rstrip("/")
        filename = f"{random_str(8)}_{random_num(6)}.txt"
        content = f"{random_str(12)}"
        target_url = f"{url}/{filename}"
        try:
            if method == "PUT":
                r1 = requests.put(target_url, data=content, headers=self.requests.headers, verify=False)
            else:
                files = {'file': (filename, content)}
                r1 = requests.post(self.requests.hostname, files=files, headers=self.requests.headers, verify=False)
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
        if self.requests.url.count("/") > int(conf.max_dir) + 2:
            return
        if not "OSS" in self.fingerprints.webserver and conf.level != 0:
            test_methods = ["PUT"] if conf.level <= 2 else ["PUT", "POST"]
            for method in test_methods:
                if r := self._test_upload(method):
                    r1, r2 = r
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": r1.url, 
                        "vultype": VulType.FILEUPLOAD
                        })
                    result.step("Request1", {
                        "request": self.requests.raw, 
                        "response": generateResponse(r1), 
                        "desc": f"Target URL: {r1.url}"
                        })
                    result.step("Request2", {
                        "request": f"GET {r2.url}", 
                        "response": generateResponse(r2), 
                        "desc": "Content matches verification string"
                        })
                    self.success(result)
                    return