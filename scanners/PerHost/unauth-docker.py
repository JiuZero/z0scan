#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-docker"
    version = "2025.9.12"
    desc = "Docker Unauthorized Access"
    ports = [2375]
    fingers = []
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            socket.setdefaulttimeout(2)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            payload = "GET /containers/json HTTP/1.1\r\nHost: %s:%s\r\n\r\n" % (ip, port)
            s.send(payload.encode())
            recv = s.recv(1024)
            if b"HTTP/1.1 200 OK" in recv and b'Docker' in recv and b'Api-Version' in recv:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": "tcp://" + self.host, 
                    "vultype": VulType.UNAUTH, 
                    })
                result.step("Socket-Request", {
                    "position": None,
                    "request": str(payload), 
                    "response": str(recv.decode('utf-8', 'ignore')), 
                    "desc": ""
                    })
                self.success(result)
        except Exception as e:
            pass
