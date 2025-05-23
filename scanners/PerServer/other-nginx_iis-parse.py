#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

from urllib.parse import urlparse
import requests

from lib.helper.compare import compare
from api import generateResponse, conf, KB, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "other-nginx_iis-parse"
    desc = 'Iis/Nginx Parse'
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if (k == "IIS" and compare("7.0", "7.5", v)) or (k == "NGINX" and compare("0.0.1", "0.8.37", v)):
                return True
        return False
        
    def audit(self):
        if self.condition():
            headers = self.requests.headers.copy()
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            ContentType = r.headers.get("Content-Type", '')
            if 'html' in ContentType and "allow" in r.text:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.OTHER
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Content-Type:{}".format(ContentType)
                    })
                self.success(result)
