#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-memcached"
    version = "2025.9.12"
    desc = "Memcached Unauthorized Access"
    ports = [11211]
    fingers = [b'MemCache|MemCache|^ERROR\r\n',]
    
    def audit(self):
        ip, port = self.host.split(":")
        socket.setdefaulttimeout(2)
        payload = b'\x73\x74\x61\x74\x73\x0a'  # command:stats
        s = socket.socket()
        socket.setdefaulttimeout(5)
        try:
            s.connect((ip, port))
            s.send(payload)
            recvdata = s.recv(2048)  # response larger than 1024
            s.close()
            if recvdata and (b'STAT version' in recvdata):
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.host, 
                    "vultype": VulType.UNAUTH, 
                    })
                result.step("Socket-Request", {
                    "position": None,
                    "request": str(payload), 
                    "response": str(recvdata.decode('utf-8', 'ignore')), 
                    "desc": ""
                    })
                self.success(result)
        except Exception as e:
            pass
