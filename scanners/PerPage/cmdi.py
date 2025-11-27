#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero/z0scan

import hashlib, re
from urllib.parse import quote
from lib.core.settings import acceptedExt
from lib.api.reverse_api import reverseApi
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, PluginBase, Threads, KB

def getmd5(s):
    m = hashlib.md5()
    if not isinstance(s, str):
        s = str(s)
    b = s.encode(encoding='utf-8')
    m.update(b)
    return m.hexdigest()

class Z0SCAN(PluginBase):
    name = "cmdi"
    desc = 'Command Execution'
    version = "2025.11.20"
    risk = 3
        
    def audit(self):
        url = self.requests.url
        if conf.level == 0:
            return
        if not self.fingerprints.waf and self.requests.suffix in acceptedExt:
            num1 = random_num(4)
            num2 = random_num(4)
            num1_num2 = num1 + num2
            num1num2 = num1 * num2
            num1_md5 = getmd5(num1)
            payloads = (
                {"cmd": "\nexpr {} + {}\n".format(num1, num2), "show": num1_num2},
                {"cmd": "|expr {} + {}".format(num1, num2), "show": num1_num2},
                {"cmd": "$(expr {} + {})".format(num1, num2), "show": num1_num2},
                {"cmd": "&set /A {}+{}".format(num1, num2), "show": num1_num2},
                {"cmd": "${@var_dump(md5(%s))};" % num1, "show": num1_md5},
                {"cmd": "{}*{}".format(num1,num2), "show": num1num2},
                {"cmd": "'-var_dump(md5(%s))-'" % num1, "show": num1_md5},
                {"cmd": "/*1*/{{%s+%s}}" % (num1, num2), "show": num1_num2},
                {"cmd": "${%s+%s}" % (num1, num2), "show": num1_num2},
                {"cmd": "${(%s+%s)?c}" % (num1, num2), "show": num1_num2},
                {"cmd": "#set($c=%s+%s)${c}$c" % (num1, num2), "show": num1_num2},
                {"cmd": "<%- {}+{} %>".format(num1, num2), "show": num1_num2},
            )

            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="cmdi")
            z0thread.submit(self.process, iterdatas, payloads)
                
    def process(self, _, payloads):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.MULTIPART_DATA, PLACE.XML_DATA]:
            return
        for _payload in payloads:
            payload = self.insertPayload({
                "key": k, 
                "payload": _payload.get("cmd"), 
                "position": position, 
                })
            r = self.req(position, payload)
            if r != None and str(_payload.get("show")) in r.text:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.CMD_INNJECTION, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": _payload.get("cmd"), 
                        }
                    })
                result.step("Request1", {
                    "position": position,
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Payload: {}".format(_payload.get("cmd"))
                    })
                self.success(result)
                break
        # 试试执行 set|set&set？
        rules = [
            'Path=[\s\S]*?PWD=',
            'Path=[\s\S]*?PATHEXT=',
            'Path=[\s\S]*?SHELL=',
            'Path\x3d[\s\S]*?PWD\x3d',
            'Path\x3d[\s\S]*?PATHEXT\x3d',
            'Path\x3d[\s\S]*?SHELL\x3d',
            'SERVER_SIGNATURE=[\s\S]*?SERVER_SOFTWARE=',
            'SERVER_SIGNATURE\x3d[\s\S]*?SERVER_SOFTWARE\x3d',
            'Non-authoritative\sanswer:\s+Name:\s*',
            'Server:\s*.*?\nAddress:\s*'
        ]
        payload = self.insertPayload({
            "key": k, 
            "payload": "set|set&set", 
            "position": position, 
            })
        r = self.req(position, payload)
        if not r:
            return
        html1 = r.text
        for rule in rules:
            if re.search(rule, html1, re.I | re.S | re.M):
                result = self.new_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": r.url, 
                    "vultype": VulType.CMD_INNJECTION, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": "set|set&set", 
                        }
                    })
                result.step("Request1", {
                    "position": position,
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Payload: {}".format("set|set&set")
                    })
                self.success(result)
                return