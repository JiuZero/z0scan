#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/11

import re
from api import VulType, KB, PluginBase, Type, conf, generateResponse


class Z0SCAN(PluginBase):
    name = "trave-list"
    desc = "Directory browsing vulnerability (Directory-based)"
    version = "2025.5.11"
    risk = 2

    def audit(self):
        if self.requests.url.count("/") > int(conf.max_dir) + 2:
            return
        if conf.level == 0:
            return
        resp_str = self.response.text
        flag_list = [
            "directory listing for",
            "<title>directory",
            "<head><title>index of",
            '<table summary="directory listing"',
            'last modified</a>',
        ]
        for i in flag_list:
            if i in resp_str.lower():
                result = self.generate_result()
                result.main({
                    "type": Type.ANALYZE,
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE
                    })
                result.step("Request1", {
                    "request": self.requests.raw, 
                    "response": self.response.raw, 
                    "desc": "{}".format(i)
                    })
                self.success(result)
                return
        # Vulscan
        match = re.search(r"<title>(.*?)</title>", resp_str.lower(), re.DOTALL)
        if not match:
            return
        title = match.group(1)
        if "index of" in title or "everything" in title:
            result = self.generate_result()
            result.main({
                "type": Type.ANALYZE,
                "url": self.requests.url, 
                "vultype": VulType.SENSITIVE
                })
            result.step("Request1", {
                "request": self.requests.raw, 
                "response": self.response.raw, 
                "desc": '"index of" in title or "everything" in title'
                })
            self.success(result)
            return
        
