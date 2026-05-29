#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/9/12

import pymongo
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-mongodb"
    version = "2025.9.12"
    desc = "Mongodb Unauthorized Access"
    risk = 2
    ports = [27017]
    fingers = [b'Mongodb|Mongodb|MongoDB']
    
    def audit(self):
        try:
            ip, port = self.host.split(":")
            conn = pymongo.MongoClient(host=ip, port=27017, serverSelectionTimeoutMS=2)
            database_list = conn.list_database_names()
            if not database_list:
                conn.close()
                return
            conn.close()
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": "tcp://" + self.host, 
                "vultype": VulType.UNAUTH, 
                })
            self.success(result)
        except Exception as e:
            pass
