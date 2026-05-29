#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import requests, base64
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB, Threads

class Z0SCAN(_PluginBase):
    name = "leakpwd-activemq"
    version = "2025.11.21"
    desc = "Weak Password on ActiveMQ"
    risk = 2
    ports = [8161]
    fingers = []
    
    def __init__(self):
        self.right_pwd = None
        self.userpass = []
        for user in conf.dicts["activemq-username"]:
            for pwd in conf.dicts["activemq-password"]:
                self.userpass.append((user, pwd))
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        url = "{self.requests.protocol}://{self.requests.hostname}:8161/admin/"
        z0thread = Threads(name="leakpwd-activemq")
        z0thread.submit(self.process, self.userpass, url)
        if self.right_pwd is not None:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": url, 
                "vultype": VulType.WEAK_PASSWORD, 
                "show": {
                    "User/Password": "/".join(self.right_pwd)
                }
            })
            self.success(result)


    def process(self, userpwd, url):
        user, pwd = userpwd
        if self.right_pwd is None:
            data = {'Authorization':'Basic '+base64.b64encode((user+':'+pwd).encode()).decode()}
            try:
                req = requests.get(url, header=data)
                if 'Welcome'.lower() in str(req.reqinfo).lower() and "ActiveMQ Console".lower() in str(req.reqinfo).lower():
                    self.right_pwd = userpwd
                    return
            except:
                pass