#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/19

import re
from urllib.parse import quote, urlparse
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB
from helper.paramanalyzer import VulnDetector

class Z0SCAN(PluginBase):
    name = "ssrf"
    desc = 'SSRF plugin detects server-side request forgery vulnerabilities via crafted payloads.'
    version = "2025.8.19"
    risk = 2
    
    def audit(self):
        rA = reverseApi()
        if conf.level == 0:
            return
        if self.requests.suffix in acceptedExt:
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="ssrf")
            z0thread.submit(self.process, iterdatas, rA)
                
    def process(self, _, rA):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        if VulnDetector(self.requests.url).is_ssrf(k, v) or re.search("^http[s]?://", v):
            url = self.requests.url
            host = urlparse.urlparse(v).netloc.split(":")[0] if re.search("^http[s]?://", v) else self.requests.hostname
            for type in ["http", "dns"]:
                if type in KB.reverse_running_server:
                    token, fullname = self.generate(type)
                    if type == "dns":
                        fullname = "http://" + fullname
                    for url_ in set([
                        fullname, 
                        "{}#@{}".format(fullname, host),
                    ]):
                        payload = self.insertPayload({
                            "key": k, 
                            "payload": url_, 
                            "position": position, 
                            })
                        r = self.req(position, payload)
                        if not r:
                            continue
                        if rA.check(payload["token"]):
                            result = self.generate_result()
                            result.main({
                                "type": Type.REQUEST, 
                                "url": r.url, 
                                "vultype": VulType.SSRF, 
                                "show": {
                                    "Position": f"{position} >> {k}", 
                                    "Payload": url_,
                                    "Msg": "Receive from Dnslog",
                                    }
                                })
                            result.step("Request1", {
                                "position": position,
                                "request": r.reqinfo, 
                                "response": generateResponse(r), 
                                "desc": "Payload: {} Receive from Dnslog".format(url_),
                                })
                            self.success(result)
                            break
                
