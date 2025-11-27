#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
import requests as req
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-jenkins"
    version = "2025.9.12"
    desc = "Jenkins Unauthorized Access"
    risk = 2
    ports = [8080]
    fingers = []
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            response1 = req.get(url=ip + "/script")
            response2 = req.get(url=ip + "/ajaxBuildQueue")
            if (response1.status_code == 200 and "Jenkins.instance.pluginManager.plugins" in response1.text  and response2.status_code==200):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": "tcp://" + self.host, 
                    "vultype": VulType.UNAUTH, 
                    })
                self.success(result)
            else:
                response1 = req.get(url=ip + "/jenkins/script")
                response2 = req.get(url=ip + "/jenkins/ajaxBuildQueue")
                if (response1.status_code == 200 and "Jenkins.instance.pluginManager.plugins" in response1.text  and response2.status_code==200):
                    result.main({
                        "type": Type.REQUEST, 
                        "url": "tcp://" + self.host, 
                        "vultype": VulType.UNAUTH, 
                        })
                    self.success(result)
        except:
            pass