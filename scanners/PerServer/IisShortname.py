#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/1

import requests
from urllib.parse import urlparse
from api import WEB_SERVER, VulType, PLACE, HTTPMETHOD, Type, ResultObject, PluginBase, KB, generateResponse

class Z0SCAN(PluginBase):
    name = "IisShortName"
    desc = 'Iis File ShortName'

    def __init__(self):
        super().__init__()
        self.existed_path = '/*~1*/a.aspx'  # 存在的文件/文件夹
        self.not_existed_path = '/JiuZero~1*/a.aspx'  # 不存在的文件/文件夹
        
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == WEB_SERVER.IIS:
                return True
        return False
        
    def audit(self):
        if self.condition():
            r1 = requests.get(self.requests.netloc + self.existed_path)
            status_1 = r1.status_code
            r2 = requests.get(self.requests.netloc + self.not_existed_path)
            status_2 = r2.status_code
            if status_1 == 404 and status_2 != 404:
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, "{} | {}".format(r1.url, r2.url), VulType.SENSITIVE, PLACE.URL)
                result.add_detail("Request", r1.reqinfo, generateResponse(r1), "Request1 Status Code is 404, but request2 isn't 404")
                result.add_detail("Request", r2.reqinfo, generateResponse(r2), "Request1 Status Code is 404, but request2 isn't 404")
                self.success(result)
                return True
            r1 = requests.options(self.requests.netloc + self.existed_path)
            status_1 = r1.status_code
            r2 = requests.options(self.requests.netloc + self.not_existed_path)
            status_2 = r2.status_code
            if status_1 == 404 and status_2 != 404:
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, "{} | {}".format(r1.url, r2.url), VulType.SENSITIVE, PLACE.URL)
                result.add_detail("Request", r1.reqinfo, generateResponse(r1), "Request1 Status Code is 404, but request2 isn't 404")
                result.add_detail("Request", r2.reqinfo, generateResponse(r2), "Request1 Status Code is 404, but request2 isn't 404")
                self.success(result)
                return True