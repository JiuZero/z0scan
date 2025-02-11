#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/2/11

import re
import requests
from urllib.parse import urlparse
from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.data import KB

class Z0SCAN(PluginBase):
    name = '可能的Bucket接管漏洞'

    def audit(self):
        if KB["OSS_STATE"]:
            r = requests.get(self.requests.netloc + self.variable_leakage, verify=False)
            response_text = r.text.lower()
            for keyword in [
                'no such bucket', 'bucket does not exist', 'bucket not found',
                'specified bucket does not exist', 'the specified bucket does not exist',
                'bucketyouare trying to access does not exist', 'bucket is not found',
                'bucket doesnotexist', 'bucketnotfound', 'nosuchbucket']:
                if keyword in response_text:
                    result = self.new_result()
                    result.init_info(self.requests.url, "可能的Bucket接管漏洞", VulType.TAKEOVER)
                    result.add_detail(
                        "Payload请求",
                        r.reqinfo,
                        generateResponse(r),
                        "发现Bucket接管漏洞：目标Bucket未配置或已被删除",
                        "匹配到的KeyWord",
                        keyword,
                        PLACE.URI
                    )
                    self.success(result)