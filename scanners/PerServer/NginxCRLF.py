#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from urllib.parse import urlparse
from lib.core.common import generateResponse
from lib.core.enums import WEB_SERVER, VulType, PLACE, HTTPMETHOD
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.data import KB


class Z0SCAN(PluginBase):
    name = 'NGINX配置错误-CRLF注入'

    def __init__(self):
        super().__init__()
        self.clrf_path = r'/%0d%0aDetectify:%20clrf'

    def audit(self):
        if KB["SERVER_VERSION"][WEB_SERVER.NGINX]:
            r = requests.get(self.requests.netloc + self.clrf_path, verify=False)
            if "Detectify" in r.headers:
                ContentType = r.headers.get("Content-Type", '')
                result = self.new_result()
                result.init_info(self.requests.url,"NGINX配置错误导-CRLF注入",VulType.SENSITIVE)
                result.add_detail("Payload请求", r.reqinfo, generateResponse(r),
                    "Content-Type:{}".format(ContentType), "", "", PLACE.URI)
                self.success(result)