#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import socket
from smb.SMBConnection import SMBConnection
from api import Threads, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "leakpwd-smb"
    version = "2025.9.12"
    desc = "Weak Password on SMB Server"
    risk = 2
    ports = [445]
    fingers = [b'SMB|SMB|^\0\0\0.\xffSMBr\0\0\0\0.*', b'SMB|SMB|^\x83\x00\x00\x01\x8f']
    
    def __init__(self):
        self.right_pwd = None
        self.userpass = []
        for user in conf.dicts["smb-username"]:
            for pwd in conf.dicts["smb-password"]:
                self.userpass.append((user, pwd))
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        z0thread = Threads(name="leakpwd-smb")
        z0thread.submit(self.process, self.userpass)
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
        user, pwd = userpwd
        if self.right_pwd is None:
            conn = SMBConnection(user, pwd, "client", self.ip, use_ntlm_v2=True, is_direct_tcp=True)
            try:
                smb_authentication_successful = conn.connect(self.ip, self.ip, timeout=6)
                if smb_authentication_successful:
                    self.right_pwd = userpwd
                conn.close()
            except Exception as e:
                pass
            finally:
                conn.close()
