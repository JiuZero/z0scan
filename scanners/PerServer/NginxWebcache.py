#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

import requests
from urllib.parse import urlparse

from api import generateResponse, WEB_SERVER, VulType, PLACE, HTTPMETHOD, ResultObject, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = "NginxWebcache"
    desc = 'Nginx Webcache Clear'

    def __init__(self):
        super().__init__()
        
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == WEB_SERVER.NGINX and 3 in conf.level:
                return True
        return False
        
    def audit(self):
        if self.condition():
            r = requests.request("PURGE", self.requests.netloc + "/*", allow_redirects=True, verify=False)
            if r.status_code == 204:
                result = self.new_result()
                result.init_info(Type.Request, self.requests.netloc, self.requests.url, VulType.SENSITIVE, PLACE.URL)
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Status Code is 204")
                self.success(result)