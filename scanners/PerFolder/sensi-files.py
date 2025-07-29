#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/26

import re
import requests
from config.others.SensiFile import rules
from api import conf, generateResponse, VulType, KB, PluginBase, Type, Threads


class Z0SCAN(PluginBase):
    name = "sensi-files"
    desc = 'Sensitive File Leak (e.g., phpinfo, .git)'
    version = "2025.6.26"
    risk = 1
    
    def audit(self):
        if self.requests.url.count("/") > int(conf.max_dir) + 2:
            return
        if 1 in conf.risk and conf.level != 0 and not self.name in KB.disable:
            z0thread = Threads(name="sensi-files")
            z0thread.submit(self.process, rules)

    def process(self, info):
        try:
            if info.get("skipwaf", False) and self.fingerprints.waf:
                return
            if info.get("phpinfo", False) and not "PHP" in self.fingerprints.webserver:
                return
            if self.requests.url.count("/") <= info.get("max_dir", 8) + 2:
                url = self.requests.rstrip("/").url + info.get("path")
                r = requests.get(url, headers=self.requests.headers)
                if r != None:
                    res = str(r.status_code).startswith(str(info.get("state_code"))) if info.get("state_code") else True
                    if res and re.search(info.get("contains"), r.content, re.I | re.S):
                        if info.get("phpinfo", False):
                            from lib.helper.helper_phpinfo import get_phpinfo
                            pinfo = get_phpinfo(r.text)
                        show = {"Msg": pinfo} if pinfo else None
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": r.url, 
                            "vultype": VulType.SENSITIVE,
                            "show": show, 
                            })
                        result.step("Request1", {
                            "request": r.reqinfo, 
                            "response": generateResponse(r), 
                            "desc": info.get("vulmsg"), 
                            })
                        self.success(result)
        except Exception as ex:
            pass
