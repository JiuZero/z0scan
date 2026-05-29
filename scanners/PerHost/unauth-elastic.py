#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import requests, re
from elasticsearch import Elasticsearch

from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-elastic"
    version = "2025.11.25"
    desc = "Elasticsearch Unauthorized Access"
    risk = 2
    ports = [9200, 9300]
    fingers = []
    
    def audit(self):
        self.ip, self.port = self.host.split(":")
        try:
            es = Elasticsearch("{}:{}".format(self.ip, self.port), timeout=20)  # 连接Elasticsearch,延时5秒
            es.indices.create(index='unauth_text')
            es.index(index="unauth_text", doc_type="test-type", id=2, body={"text": "text"})
            ret = es.get(index="unauth_text", doc_type="test-type", id=2)
            es.indices.delete(index='unauth_text')
            nodes = None
            try:
                text = es.cat.indices()
                nodes = re.findall(r'open ([^ ]*) ', text)
            except Exception:
                pass
            result = self.generate_result()
            datas = {
                "type": Type.REQUEST, 
                "url": self.host, 
                "vultype": VulType.UNAUTH, 
                }
            if nodes is not None:
                datas["show"] = {
                    "Nodes": nodes, 
                }
            result.main(datas)
            self.success(result)
            return
        except Exception as e:
            pass