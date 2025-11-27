#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import requests
from api import VulType, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-solr"
    version = "2025.9.12"
    desc = "Apache Solr Unauthorized Access"
    risk = 2
    ports = [8983]
    fingers = []
    
    def audit(self):
        try:
            url = 'http://' + self.host + '/solr/'
            r = requests.get(url)
            if r.status_code == 200 and 'Solr Admin' in r.text and 'Dashboard' in r.text:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": url, 
                    "vultype": VulType.UNAUTH, 
                    })
                self.success(result)
        except Exception:
            pass
    