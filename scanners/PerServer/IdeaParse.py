#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/3/2

from urllib.parse import urlparse
import requests
from lxml import etree
from api import KB, conf, generateResponse, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "IdeaParse"
    desc = 'Idea Parse'
    
    def condition(self):
        if not KB["WAFSTATE"] and 3 in conf.level:
            return True
        return False
        
    def audit(self):
        if self.condition():
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + ".idea/workspace.xml"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            path_lst = []
            if '<component name="' in r.text:
                root = etree.XML(r.text.encode())
                for e in root.iter():
                    if e.text and e.text.strip().find('$PROJECT_DIR$') >= 0:
                        path = e.text.strip()
                        path = path[path.find('$PROJECT_DIR$') + 13:]
                        if path not in path_lst:
                            path_lst.append(path)
                    for key in e.attrib:
                        if e.attrib[key].find('$PROJECT_DIR$') >= 0:
                            path = e.attrib[key]
                            path = path[path.find('$PROJECT_DIR$') + 13:]
                            if path and path not in path_lst:
                                path_lst.append(path)
                if path_lst:
                    result = self.new_result()
                    result.init_info(Type.REQUEST, self.requests.hostname, r.url, VulType.OTHER, PLACE.URL, msg="Dir List: {}".format(repr(path_lst)))
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Dir List: {}".format(repr(path_lst)))
                    self.success(result)
