#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/9/27
# JiuZero 2025/6/22

import requests
from requests import Request, Session
from api import VulType, Type, PLACE, PluginBase, generateResponse, conf, KB

class Z0SCAN(PluginBase):
    name = 'smuggling'
    desc = 'Request Smuggling Vulnerability'
    version = "2025.6.22"
    risk = 3

    def audit(self):
        if not self.risk in conf.risk or conf.level == 0:
            return
        # bug太多了 后面再修吧
        # https://github.com/w-digital-scanner/w13scan/issues/459
        # https://github.com/w-digital-scanner/w13scan/issues/457
        url = self.requests.url
        headers = self.requests.headers
        cycle = 5

        if self.response.status_code != 200:
            return
        # request_smuggling_cl_te
        for i in range(cycle):
            payload_headers = {
                "Content-Length": "6",
                "Transfer-Encoding": "chunked"
            }
            data = b'0\r\n\r\nS'.decode()
            temp_header = headers.copy()
            for k, v in payload_headers.items():
                if k.lower() in temp_header:
                    temp_header[k.lower()] = v
                else:
                    temp_header[k] = v
            try:
                r = requests.post(url, headers=temp_header, data=data, timeout=30)
            except:
                continue
            if r.status_code == 403 and self.response.text != r.text:
                r2 = requests.get(url, headers=headers)
                if r2 == 200:
                    result = self.generate_result()
                    result.main({
                        "type": Type.ANALYZE, 
                        "url": self.requests.url, 
                        "vultype": VulType.OTHER, 
                        "show": {
                            "Msg": "CL.TE Smuggling", 
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": f"Deformity package"
                        })
                    result.step("Request2", {
                        "request": r2.reqinfo, 
                        "response": generateResponse(r2), 
                        "desc": f"Normal access"
                        })
                    self.success(result)
                    return
        # request_smuggling_te_cl
        for i in range(cycle + 1):
            payload_headers = {
                "Content-Length": "3",
                "Transfer-Encoding": "chunked"
            }
            data = b'1\r\nD\r\n0\r\n\r\n'.decode()
            req = Request('POST', url, data=data, headers=headers)
            prepped = req.prepare()
            for k, v in payload_headers.items():
                if k.lower() in prepped.headers:
                    del prepped.headers[k.lower()]
                prepped.headers[k] = v
            s = Session()
            try:
                r = s.send(prepped)
            except:
                continue
            if r.status_code == 403 and self.response.text != r.text:
                r2 = requests.get(url, headers=headers)
                if r2.status_code == 200:
                    result = self.generate_result()
                    result.main({
                        "type": Type.ANALYZE, 
                        "url": self.requests.url, 
                        "vultype": VulType.SENSITIVE, 
                        "show": {
                            "Msg": "TE.CL Smuggling", 
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": f"Deformity package"
                        })
                    result.step("Request2", {
                        "request": r2.reqinfo, 
                        "response": generateResponse(r2), 
                        "desc": f"Normal access"
                        })
                    self.success(result)
                    return
