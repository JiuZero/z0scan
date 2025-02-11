#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/2/9

import uuid
import config
import requests
import hashlib
from urllib.parse import urlparse
from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.data import conf, KB
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase

class Z0SCAN(PluginBase):
    name = 'OSS存储桶任意文件上传漏洞'
    
    def audit(self):
        if KB["OSS_STATE"]:
            test_filename = f"Z0_test_{uuid.uuid4().hex}.txt"
            test_content = f"Z0_OSS_TEST_CONTENT_{uuid.uuid4().hex}"
            content_md5 = hashlib.md5(test_content.encode()).hexdigest()
            upload_url = f"{self.requests.netloc}/{test_filename}"

            try:
                pr = requests.put(
                    upload_url,
                    headers=self.requests.headers,
                    data=test_content,
                    verify=False,
                    timeout=conf.timeout,
                    allow_redirects=False
                )
                if pr.status_code in [200, 201, 204]:
                    etag = pr.headers.get('ETag', '').strip('"')
                    if etag == content_md5:
                        gr = requests.get(
                            upload_url,
                            verify=False,
                            timeout=15,
                            allow_redirects=False
                        )

                        if gr.status_code == 200 and test_content in gr.text:
                            result = ResultObject(self)
                            result.init_info(
                                self.requests.url,
                                "OSS存储桶任意文件上传漏洞",
                                VulType.FILEUPLOAD
                            )
                            result.add_detail(
                                "OSS文件上传验证",
                                pr.reqinfo,
                                generateResponse(pr),
                                f"ETag验证通过({etag})且内容可读",
                                upload_url,
                                "",
                                PLACE.PUT
                            )
                            self.success(result)
                            try:
                                requests.delete(upload_url, timeout=10, verify=False)
                            except:
                                pass
            except Exception as e:
                pass