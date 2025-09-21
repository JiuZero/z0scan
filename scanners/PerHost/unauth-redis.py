#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-resis"
    version = "2025.9.12"
    desc = "Redis Unauthorized Access"
    ports = [6379]
    fingers = [b'^-ERR unknown command', b'^-ERR wrong number of arguments', b'^-DENIED Redis is running']
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            s = socket.socket()
            s.connect((ip, port))
            payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
            s.send(payload)
            data = s.recv(1024)
            s.close()
            if b"redis_version" in data:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": "tcp://" + self.host, 
                    "vultype": VulType.UNAUTH, 
                    })
                result.step("Socket-Request", {
                    "position": None,
                    "request": str(payload), 
                    "response": str(data.decode('utf-8', 'ignore')), 
                    "desc": ""
                    })
                self.success(result)
        except:
            s.close()
