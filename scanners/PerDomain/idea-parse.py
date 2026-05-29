#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero/z0scan

from urllib.parse import urlparse
import requests
from lxml import etree
from api import KB, conf, generateResponse, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "idea-parse"
    desc = 'Idea Parse'
    version = "2025.3.2"
    risk = 1
    
    def audit(self):
        if conf.level != 0 and not self.fingerprints.waf: # WAF可能会拦截对包含.idea的访问
            headers = self.requests.headers.copy()
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + ".idea/workspace.xml"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            if r is None: return
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
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": r.url, 
                        "vultype": VulType.OTHER, 
                        "show": {
                            "Msg": "Dir List: {}".format(repr(path_lst))
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Dir List: {}".format(repr(path_lst))
                        })
                    self.success(result)
