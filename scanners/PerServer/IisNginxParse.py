#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlparse

import requests

from lib.core.common import generateResponse
from lib.core.data import conf, KB
from lib.helper.compare import compare
from lib.core.enums import WEB_SERVER, VulType, PLACE
from lib.core.plugins import PluginBase


class Z0SCAN(PluginBase):
    name = 'IIS/Nginx解析漏洞'

    def audit(self):
        if (KB["SERVER_VERSION"][WEB_SERVER.IIS] or KB["SERVER_VERSION"][WEB_SERVER.NGINX]) and (compare("7.0", "7.5", KB["SERVER_VERSION"][WEB_SERVER.IIS]) or compare("0.0.1", "0.8.37", KB["SERVER_VERSION"][WEB_SERVER.NGINX])):
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            ContentType = r.headers.get("Content-Type", '')
            if 'html' in ContentType and "allow" in r.text:
                result = self.new_result()
                result.init_info(self.requests.url, "IIS/Nginx解析漏洞", VulType.CODE_INJECTION)
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                  "Content-Type:{}".format(ContentType), "", "", PLACE.GET)
                self.success(result)
