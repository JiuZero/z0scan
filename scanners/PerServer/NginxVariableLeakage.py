#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/2/9
# @File    : Nginx_VariableLeakage.py

import requests
from urllib.parse import urlparse
from lib.core.data import conf, KB
from lib.core.common import generateResponse
from lib.core.enums import WEB_SERVER, VulType, PLACE, HTTPMETHOD
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase


class Z0SCAN(PluginBase):
    name = 'NGINX配置错误导-变量泄露'

    def __init__(self):
        super().__init__()
        self.variable_leakage = r'/foo$http_referer'

    def audit(self):
        if KB["SERVER_VERSION"][WEB_SERVER.NGINX] or conf.level == 3:
            headers={"Referer": "bar"}
            r = requests.get(self.requests.netloc + self.variable_leakage, headers=headers, verify=False)
            if r.status_code == 204:
                result = self.new_result()
                result.init_info(self.requests.url,"NGINX配置错误导-变量泄露",VulType.SENSITIVE)
                result.add_detail("Payload请求", r.reqinfo, generateResponse(r), "", "", "", PLACE.URI)
                self.success(result)