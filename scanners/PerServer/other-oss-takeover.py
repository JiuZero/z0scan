#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

import re
import requests
from urllib.parse import urlparse

from api import generateResponse, VulType, PLACE, Type, PluginBase, KB, conf

class Z0SCAN(PluginBase):
    name = "other-oss-takeover"
    desc = 'OSS Bucket Takeover'
    version = "2025.3.3"
    risk = 3

    def audit(self):
        if not "OSS" in self.fingerprints.webserver and 3 in conf.risk:
            r = requests.get(self.requests.url, verify=False)
            response_text = r.text.lower()
            for keyword in [
                'no such bucket', 'bucket does not exist', 'bucket not found',
                'specified bucket does not exist', 'the specified bucket does not exist',
                'bucketyouare trying to access does not exist', 'bucket is not found',
                'bucket doesnotexist', 'bucketnotfound', 'nosuchbucket']:
                if keyword in response_text:
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.OTHER
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Match KeyWord: {}".format(keyword)
                        })
                    self.success(result)
                    return True