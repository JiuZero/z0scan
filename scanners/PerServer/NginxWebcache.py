#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from urllib.parse import urlparse
from lib.core.common import generateResponse
from lib.core.enums import WEB_SERVER, VulType, PLACE, HTTPMETHOD
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.data import conf, KB


class Z0SCAN(PluginBase):
    name = 'NGINX配置错误导-WEB缓存清理'

    def __init__(self):
        super().__init__()

    def audit(self):
        if KB["SERVER_VERSION"][WEB_SERVER.NGINX] and conf.level == 3:
            r = requests.request("PURGE", self.requests.netloc + "/*", allow_redirects=True, verify=False)
            if r.status_code == 204:
                ContentType = r.headers.get("Content-Type", '')
                result = self.new_result()
                result.init_info(self.requests.url,"NGINX配置错误导-WEB缓存清理",VulType.SENSITIVE)
                result.add_detail("Payload请求", r.reqinfo, generateResponse(r),
                    "Content-Type:{}".format(ContentType), "", "", PLACE.URI)
                self.success(result)