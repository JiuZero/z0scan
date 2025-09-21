#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import ftplib
from api import conf, PLACE, VulType, POST_HINT, Type, _PluginBase, Threads, KB

class Z0SCAN(_PluginBase):
    name = "other-ftp-anonymous"
    version = "2025.9.12"
    desc = "FTP anonymous Login"
    ports = [21]
    fingers = [b'^220-', b'^220.*?FTP', b'^220.*?FileZilla',]
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            ftp = ftplib.FTP(ip)
            ftp.login('anonymous', 'anonymous')
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": "tcp://" + self.host, 
                "vultype": VulType.OTHER, 
                })
            self.success(result)
        except Exception as e:
            pass
