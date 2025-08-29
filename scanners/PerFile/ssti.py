#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/24

from lib.helper.ssti.importssti import importssti
from api import generateResponse, VulType, Type, PluginBase, conf, KB, Threads

class Z0SCAN(PluginBase):
    name = "ssti"
    desc = 'SSTI Vulnerability Detection'
    version = "2025.6.24"
    risk = 3

    def __init__(self):
        super().__init__()
        self.ssti_payloads = importssti()
        
    def audit(self):
        if not self.risk in conf.risk or conf.level == 0:
            return
        if self.requests.suffix.lower() not in ["", "php", "do", "action"]:
            return
        iterdatas = self.generateItemdatas()
        z0thread = Threads(name="ssti")
        z0thread.submit(self.inject, iterdatas, self.ssti_payloads)

    def inject(self, iterdata, payloads):
        k, v, position = iterdata
        for test_payload in payloads:
            payload, show, plugin = test_payload
            # php，但是plugin不是php框架，不测试
            if not "PHP" in self.fingerprints.programing:
                if plugin.lower() not in ["php", "smarty", "twig"]:
                    return
            _payload = self.insertPayload({
                "key": k, 
                "value": payload, 
                "position": position,
                })
            r = self.req(position, _payload)
            if r != None and show.encode() in r.content:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SSTI, 
                    "show": {
                        "Position": f"{position} >> {k}", 
                        "Payload": payload, 
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": payload, 
                    })


'''
dot http://127.0.0.1:15004/dot?inj=*&tpl=%s
dust http://127.0.0.1:15004/dust?inj=*&tpl=%s 
ejs http://127.0.0.1:15004/ejs?inj=*&tpl=%s
erb http://localhost:15005/reflect/erb?inj=*&tpl=%s True 采用乘法
freemarker http://127.0.0.1:15003/freemarker?inj=*&tpl=%s
Jinja2  http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*
mako http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*
marko http://127.0.0.1:15004/marko?inj=*&tpl=%s
nunjucks http://127.0.0.1:15004/nunjucks?inj=*&tpl=%s
pug http://127.0.0.1:15004/pug?inj=*&tpl=%s
slim http://localhost:15005/reflect/slim?inj=*&tpl=%s True 采用乘法
smarty http://127.0.0.1:15002/smarty-3.1.32-secured.php?inj=*&tpl=%s  True 用注释拼接字符
tornado http://127.0.0.1:15001/reflect/tornado?tpl=%s&inj=*  True 拼接字符
twig http://127.0.0.1:15002/twig-1.20.0-secured.php?tpl=%s&inj=* True 采用输出字符+<br >
velocity http://127.0.0.1:15003/velocity?inj=*&tpl=%s  True 采用输出数据类型+数字
javascript http://127.0.0.1:15004/javascript?inj=*&tpl=%s True 采用类型和数字
php http://localhost:15002/eval.php?inj=*&tpl=%s True 采用md5
ruby http://localhost:15005/reflect/eval?inj=*&tpl=%s  True 采用乘法
python http://localhost:15001/reflect/eval?inj=*&tpl=%s True  采用拼接字符
'''
