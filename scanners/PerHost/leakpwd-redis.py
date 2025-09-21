#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket
from api import Threads, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "leakpwd-redis"
    version = "2025.9.12"
    desc = "Weak Password on Redis Server"
    ports = [6379]
    fingers = [b'^-ERR unknown command', b'^-ERR wrong number of arguments', b'^-DENIED Redis is running']
    
    def __init__(self):
        self.right_pwd = None
        self.is_protected = False
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        z0thread = Threads(name="leakpwd-redis")
        z0thread.submit(self.process, conf.lists["redis-password"])
        if self.right_pwd is not None:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": "tcp://" + self.host, 
                "vultype": VulType.WEAK_PASSWORD, 
                "show": {
                    "Password": self.right_pwd
                }
            })
            self.success(result)

    def process(self, pwd):
        if self.right_pwd is None and self.is_protected is False:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(5)
                s.connect((self.ip, self.port))
                if pwd is None:
                    s.send("INFO\r\n".encode())
                    result = s.recv(1024)
                    # print("pwd:{} recv:{}".format(pwd,result))
                    if b"redis_version" in result:
                        self.right_pwd = str(pwd)
                else:
                    s.send(("AUTH %s\r\n" % (pwd)).encode())
                    result = s.recv(1024)
                    # print("pwd:{} recv:{}".format(pwd,result))
                    if b'+OK' in result:
                        self.right_pwd = pwd
                if b"running in protected" in result:
                    self.is_protected = True
            except Exception as ex:
                pass
            finally:
                s.close()
