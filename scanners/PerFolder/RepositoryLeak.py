#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/4

import re
import requests

from api import KB, conf, generateResponse, VulType, PLACE, PluginBase, Type


class Z0SCAN(PluginBase):
    name = "RepositoryLeak"
    desc = '.git .svn .bzr .hg Finder'

    def condition(self):
        # Waf通常会拦截对这类敏感文件的请求
        if not KB["WAFSTATE"] and 2 in conf.level:
            return True
        return False
        
    def audit(self):
        if self.condition():
            flag = {
                "/.svn/all-wcprops": "svn:wc:ra_dav:version-url",
                "/.git/config": 'repositoryformatversion[\s\S]*',
                "/.bzr/README": 'This\sis\sa\sBazaar[\s\S]',
                '/CVS/Root': ':pserver:[\s\S]*?:[\s\S]*',
                '/.hg/requires': '^revlogv1.*'
            }
            headers = self.requests.headers
            for f in flag.keys():
                _ = self.requests.url.rstrip('/') + f
                r = requests.get(_, headers=headers)
                if re.search(flag[f], r.text, re.I | re.S | re.M):
                    result = self.new_result()
                    result.init_info(Type.REQUEST, self.requests.hostname, r.url, VulType.SENSITIVE, PLACE.URL)
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Match {}".format(flag[f]))
                    self.success(result)
