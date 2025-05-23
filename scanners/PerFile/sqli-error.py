#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/3/13

from data.rule.sqli_error import rules
from api import generateResponse, random_num, random_str, VulType, Type, PluginBase, conf, logger
from lib.helper.helper_sensitive import sensitive_page_error_message_check
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

class Z0SCAN(PluginBase):
    name = "sqli-error"
    desc = 'SQL Error Finder'

    def condition(self):
        if conf.level == 0:
            return False
        if not self.response.waf:
            return True
        return False
        
    def audit(self):
        if self.condition():
            _payloads = [
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
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.process, _, _payloads) for _ in iterdatas
                ]
                try:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as task_e:
                            logger.error(f"Task failed: {task_e}", origin=self.name)
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                except Exception as e:
                    logger.error(f"Unexpected error: {e}", origin=self.name)
                    executor.shutdown(wait=False)
    
    def Get_sql_errors(self):
        sql_errors = []
        for database, re_strings in rules.items():
            for re_string in re_strings:
                sql_errors.append((re.compile(re_string, re.IGNORECASE), database))
        return sql_errors
    
    def process(self, _, _payloads):
        k, v, position = _
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
                            "Position": position, 
                            "Param": k, 
                            "Payload": payload, 
                            "Msg": "DBMS_TYPE Maybe {}; Match {}".format(dbms_type, match.group())
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": "Dbms Maybe {}; Match {}".format(dbms_type, match.group())
                        })
                    self.success(result)
                    return True
            message_lists = sensitive_page_error_message_check(html)
            if message_lists:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SQLI, 
                    "show": {
                        "Position": position, 
                        "Param": k, 
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
    