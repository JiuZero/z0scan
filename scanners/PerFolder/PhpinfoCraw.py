#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:27 PM
# @Author  : w8ay

import requests

from lib.core.common import generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, VulType, PLACE
from lib.core.plugins import PluginBase
from lib.helper.helper_phpinfo import get_phpinfo


class Z0SCAN(PluginBase):
    desc = '''查看此目录下是否存在phpinfo文件'''
    name = 'phpinfo遍历'

    def audit(self):
        if WEB_PLATFORM.PHP in self.response.programing and conf.level >= 2:
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
                    result.init_info(self.requests.url, "phpinfo发现", VulType.SENSITIVE)
                    result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                      '\n'.join(info), "", "", PLACE.GET)
                    self.success(result)
