#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-rsync"
    version = "2025.9.12"
    desc = "Rsync Unauthorized Access"
    ports = [873]
    fingers = [b'^@RSYNCD:', b'@RSYNCD:']
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            socket.setdefaulttimeout(1.5)
            payload = b"\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (ip, port)
            sock.connect(server_address)
            sock.sendall(payload)
            initinfo = sock.recv(400)
            if b"RSYNCD" in initinfo:
                sock.sendall(b"\x0a")
            modulelist = sock.recv(200)
            sock.close()
            if len(modulelist) > 0:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": "tcp://" + self.host, 
                    "vultype": VulType.UNAUTH, 
                    })
                self.success(result)
        except Exception as e:
            pass
