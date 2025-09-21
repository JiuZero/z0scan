#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import psycopg2
from api import Threads, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "leakpwd-postgresql"
    version = "2025.9.12"
    desc = "Weak Password on PostgreSQL Server"
    ports = [5432]
    fingers = [b'Invalid packet length', b'^EFATAL']
    
    def __init__(self):
        self.right_pwd = None
    
    def audit(self):
        try:
            self.ip, self.port = self.host.split(":")
            z0thread = Threads(name="leakpwd-postgresql")
            z0thread.submit(self.process, conf.lists["postgresql-password"])
            if self.right_pwd is not None:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": "tcp://" + self.host, 
                    "vultype": VulType.WEAK_PASSWORD, 
                    "show": {
                        "User/Password": "postgres/" + self.right_pwd,
                    }
                })
                self.success(result)
        except Exception as e:
            pass
            
    def process(self, pwd):
        try:
            pwd = pwd.replace('{user}', 'postgres')
            conn = psycopg2.connect(host=self.ip, port=self.port, user='postgres', password=pwd)
            conn.close()
            self.right_pwd = pwd
        except Exception as e:
            pass
        finally:
            conn.close()