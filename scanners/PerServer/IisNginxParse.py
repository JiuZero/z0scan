#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

from urllib.parse import urlparse
import requests

from lib.helper.compare import compare
from api import generateResponse, conf, KB, WEB_SERVER, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "IisNginxParse"
    desc = 'Iis/Nginx Parse'
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if (k == WEB_SERVER.IIS and compare("7.0", "7.5", v)) or (k == WEB_SERVER.NGINX and compare("0.0.1", "0.8.37", v)):
                return True
        return False
        
    def audit(self):
        if self.condition():
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            ContentType = r.headers.get("Content-Type", '')
            if 'html' in ContentType and "allow" in r.text:
                result = self.new_result()
                result.init_info(Type.Request, self.requests.hostname, r.url, VulType.OTHER, PLACE.URL)
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Content-Type:{}".format(ContentType))
                self.success(result)
