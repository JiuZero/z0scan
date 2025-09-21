#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import socket, binascii
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB, Threads

class Z0SCAN(_PluginBase):
    name = "leakpwd-mssql"
    version = "2025.9.12"
    desc = "Weak Password on MSSQL Server"
    ports = [1433]
    fingers = [b'MSSQLSERVER']
    
    def __init__(self):
        self.right_pwd = None
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        userpass = []
        for user in conf.lists["mssql-username"]:
            for pwd in conf.lists["mssql-password"]:
                userpass.append((user, pwd))
        z0thread = Threads(name="leakpwd-redis")
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
        if self.right_pwd is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(8)
                sock.connect((self.ip, self.port))
                hh = binascii.b2a_hex(self.ip.encode()).decode()
                husername = binascii.b2a_hex(user.encode()).decode()
                lusername = len(user)
                lpassword = len(pass_)
                ladd = len(self.ip) + len(str(self.port)) + 1
                hpwd = binascii.b2a_hex(pass_.encode()).decode()
                pp = binascii.b2a_hex(str(self.port).encode()).decode()
                address = hh + '3a' + pp
                # hhost = binascii.b2a_hex(ip.encode()).decode()
                data = "0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000"
                data1 = data.replace(data[16:16 + len(address)], address)
                data2 = data1.replace(data1[78:78 + len(husername)], husername)
                data3 = data2.replace(data2[140:140 + len(hpwd)], hpwd)
                if lusername >= 16:
                    data4 = data3.replace('0X', str(hex(lusername)).replace('0x', ''))
                else:
                    data4 = data3.replace('X', str(hex(lusername)).replace('0x', ''))
                if lpassword >= 16:
                    data5 = data4.replace('0Y', str(hex(lpassword)).replace('0x', ''))
                else:
                    data5 = data4.replace('Y', str(hex(lpassword)).replace('0x', ''))
                hladd = hex(ladd).replace('0x', '')
                data6 = data5.replace('ZZ', str(hladd))
                data7 = binascii.unhexlify(data6)
                sock.send(data7)
                packet = sock.recv(1024)
                if b'master' in packet:
                    self.right_pwd = userpwd
            except Exception as e:
                pass
            finally:
                sock.close()

