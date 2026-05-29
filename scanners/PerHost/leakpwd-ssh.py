#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import paramiko
from api import Threads, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "leakpwd-ssh"
    version = "2025.11.25"
    desc = "Weak Password on SSH Server"
    risk = 2
    ports = [22]
    fingers = []
    
    def __init__(self):
        self.right_pwd = None
        self.is_protected = False
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        userpass = []
        for user in conf.dicts["ssh-username"]:
            for pwd in conf.dicts["ssh-password"]:
                userpass.append((user, pwd))
        z0thread = Threads(name="leakpwd-ssh")
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
        username, password = userpwd
        # 创建一个ssh的客户端，用来连接服务器
        ssh = paramiko.SSHClient()
        # 创建一个ssh的白名单
        know_host = paramiko.AutoAddPolicy()
        # 加载创建的白名单
        ssh.set_missing_host_key_policy(know_host)
        try:
            # 连接服务器
            ssh.connect(
                hostname=self.ip,
                port=self.port,
                username=username,
                password=password
            )
            ssh.close()
            self.right_pwd = userpwd
            return
        except Exception as e:
            return
