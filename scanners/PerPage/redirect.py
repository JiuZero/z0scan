#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import re
from urllib.parse import urlparse, unquote
from api import generateResponse, VulType, PLACE, Type, PluginBase, conf, logger, Threads, KB, random_str
from helper.paramanalyzer import VulnDetector

class Z0SCAN(PluginBase):
    name = "redirect"
    desc = 'Redirect Vulnerability'
    version = "2025.11.21"
    risk = 1

    def _detect_redirect_type(self, response, test_domain, randomstr):
        body_patterns = [
            r"<meta[^>]*?url[\s]*?=[\s'\"]*?([^>]*?)['\"]?>", 
            r"href[\s]*?=[\s]*?['\"](.*?)['\"]", 
            r"(location|window\.location|document\.location|window)(\.open|\.navigate|\.href|\.replace|\.assign)\(['\"](.*?)['\"]\)",
        ]
        # header 检测
        if 300 <= response.status_code < 400:
            for k, v in response.headers.items():
                if 'location' in k.lower():
                    location = unquote(response.headers[k])
                    if urlparse(location).netloc.endswith(urlparse(test_domain).netloc):
                        return "HTTP Head", location
        # body 检测
        for search in body_patterns:
            for x in re.findall(search, response.text, re.I):
                if x.strip() and x.strip().startswith("http") and randomstr in x.split("?", 1)[0]:  # 确保在url头，不在参数里
                    return "Boby", x
        return None, None

    def audit(self):
        if conf.level != 0 and self.response.status_code == 302:
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="redirect")
            z0thread.submit(self.process, iterdatas)
    
    def process(self, _):
        k, v, position = _
        if VulnDetector().is_redirect(k, v):
            value = urlparse.unquote(v).strip()
            randomstr = random_str(length=6).lower()
            if re.search("^http[s]?://", value):
                p = urlparse.urlparse(value)
                port = ""
                if ":" in p.netloc:
                    netloc_, port = p.netloc.split(":", 1)
                    port = ":" + port
                else:
                    netloc_ = p.netloc
                if netloc_.count(".") < 2:
                    netloc = netloc_ + ".{}com.cn".format(randomstr)
                else:
                    netloc = netloc_ + "." + randomstr + ".".join(netloc_.split(".")[-2:])
                test_domains = [
                    f"{p.scheme}://{netloc}#@{p.netloc}{p.path}", 
                    f"{p.scheme}://{netloc}{port}", 
                    ]
            else:
                test_domains = [
                    f"http://z0.{randomstr}.#{self.requests.hostname}", 
                    f"z.{randomstr}.com"
                ]
            for test_domain in test_domains:
                payload = self.insertPayload({
                    "key": k, 
                    "position": position, 
                    "payload": self.test_domain
                    })
                r = self.req(position, payload, allow_redirects=False)
                if not r:
                    return
                vuln_type, evidence = self._detect_redirect_type(r, test_domain, randomstr)
                if not vuln_type:
                    return
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.REDIRECT, 
                    "show": {
                        "Payload": payload, 
                        "Position": f"{position} >> {k}",
                        "Msg": f"{vuln_type}", 
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"Match Keywords {evidence[:100] if evidence else ''}"
                    })
                self.success(result)
                return True