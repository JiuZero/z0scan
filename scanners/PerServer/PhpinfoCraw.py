#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/11
# JiuZero 2025/3/4

import requests

from api import generateResponse, conf, WEB_PLATFORM, VulType, PLACE, PluginBase, Type
from lib.helper.helper_phpinfo import get_phpinfo


class Z0SCAN(PluginBase):
    name = "PhpInfoCraw"
    desc = 'Phpinfo Finder'
    
    def condition(self):
        for k, v in self.response.programing.items():
            if k == WEB_PLATFORM.PHP and 4 in conf.level:
                return True
        return False
        
    def audit(self):
        if self.condition():
            headers = self.requests.headers
            variants = [
                "phpinfo.php",
                "pi.php",
                "php.php",
                "i.php",
                "test.php",
                "temp.php",
                "info.php",
            ]
            for phpinfo in variants:
                testURL = self.requests.url.rstrip("/") + "/" + phpinfo
                r = requests.get(testURL, headers=headers)
                flag = "<title>phpinfo()</title>"
                if flag in r.text:
                    info = get_phpinfo(r.text)
                    result = self.new_result()
                    result.init_info(Type.REQUEST, self.requests.hostname, r.url, VulType.SENSITIVE, PLACE.URL)
                    result.add_detail("Request", r.reqinfo, generateResponse(r), '\n'.join(info))
                    self.success(result)
