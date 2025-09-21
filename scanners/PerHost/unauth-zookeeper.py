#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-zookeeper"
    version = "2025.9.12"
    desc = "Zookeeper Unauthorized access"
    ports = [2181]
    fingers = [b'Zookeeper|Zookeeper|^Zookeeper version: ']
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            socket.setdefaulttimeout(2)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send(b'success')
            data = s.recv(1024)
            if b'Environment' in data:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": "tcp://" + self.host, 
                    "vultype": VulType.UNAUTH, 
                    })
                self.success(result)
        except Exception as e:
            pass
