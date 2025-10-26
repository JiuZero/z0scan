#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket, pymysql
from api import conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB, Threads

'''
pymysql.err.OperationalError: (1045, "Access denied for user 'root'@'localhost' (using password: YES)")
pymysql.err.OperationalError: (1130, "xx.xx.x.x' is not allowed to connect to this MySQL server")

'''

class Z0SCAN(_PluginBase):
    name = "leakpwd-mysql"
    version = "2025.9.12"
    desc = "Weak Password on MySQL Server"
    ports = [3306]
    fingers = [b'mysql_native_password', b'^\x19\x00\x00\x00\x0a', b'^\x2c\x00\x00\x00\x0a', b'hhost \'', b'khost \'', b'mysqladmin', b'whost \'', b'^[.*]\x00\x00\x00\n.*?\x00', b'this MySQL server', b'MariaDB server', b'\x00\x00\x00\xffj\x04Host']
    def __init__(self):
        self.right_pwd = None
        self.allow_connect = True
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        userpass = []
        for user in conf.dicts["mysql-username"]:
            for pwd in conf.dicts["mysql-password"]:
                userpass.append((user, pwd))
        z0thread = Threads(name="leakpwd-mysql")
        z0thread.submit(self.process, userpass)
        if self.right_pwd is not None:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": "tcp://" + self.host, 
                "vultype": VulType.WEAK_PASSWORD, 
                "show": {
                    "User/Password": "/".join(self.right_pwd)
                }
            })
            self.success(result)

    def process(self, userpwd):
        user, pass_ = userpwd
        if self.right_pwd is None and self.allow_connect:
            try:
                pymysql.connect(self.ip, user, pass_, port=self.port)
                self.right_pwd = userpwd
            except Exception as e:
                if "not allowed to connect to" in str(e):
                    self.allow_connect = False
