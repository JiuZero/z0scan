#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/11/5

import re
from api import VulType, KB, PluginBase, Type, conf, generateResponse


class Z0SCAN(PluginBase):
    name = "trave-list"
    desc = "Directory browsing vulnerability (Directory-based)"
    version = "2025.11.5"
    risk = 2

    def audit(self):
        if self.requests.url.count("/") > int(conf.max_dir) + 2:
            return
        if conf.level == 0:
            return
        resp_str = self.response.text
        flag_list = [
            r"directory listing for",
            r"<title>directory",
            # r'<title>index of ', 
            r'<a href="?c=n;o=d">name</a>', 
            r'<table summary="directory listing"',
            r'last modified</a>', 
            r'parent directory</a>', 
            r'<title>folder listing.', 
            r'&lt;dir&gt; <a href="/', 
            r'''<pre><a href="/">\[''', 
            r'">[to parent directory]</a><br><br>',
            
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
        
