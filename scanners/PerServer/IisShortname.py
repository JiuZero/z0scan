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
    name = 'IIS短文件名漏洞检测'

    def __init__(self):
        super().__init__()
        # 定义存在的文件/文件夹和不存在文件/文件夹的测试路径
        self.existed_path = '/*~1*/a.aspx'  # 存在的文件/文件夹
        self.not_existed_path = '/l1j1e*~1*/a.aspx'  # 不存在的文件/文件夹

    def audit(self):
        """检测是否存在IIS短文件名漏洞"""
        if KB["SERVER_VERSION"][WEB_SERVER.IIS]:
            r = requests.get(self.requests.netloc + self.existed_path)
            status_1 = r.status_code
            r = requests.get(self.requests.netloc + self.not_existed_path)
            status_2 = r.status_code
            if status_1 == 404 and status_2 != 404:
                ContentType = r.headers.get("Content-Type", '')
                result = self.new_result()
                result.init_info(self.requests.url,"IIS短文件名漏洞",VulType.SENSITIVE)
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                    "Content-Type:{}".format(ContentType), "", "", PLACE.URI)
                self.success(result)
            r = requests.options(self.requests.netloc + self.existed_path)
            status_1 = r.status_code
            r = requests.options(self.requests.netloc + self.not_existed_path)
            status_2 = r.status_code
            if status_1 == 404 and status_2 != 404:
                ContentType = r.headers.get("Content-Type", '')
                result = self.new_result()
                result.init_info(self.requests.url,"IIS短文件名漏洞",VulType.SENSITIVE)
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                    "Content-Type:{}".format(ContentType), "", "", PLACE.URI)
                self.success(result)