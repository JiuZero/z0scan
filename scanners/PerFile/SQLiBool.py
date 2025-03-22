#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/30
# JiuZero 2025/3/13

import copy
import difflib
import re
import random
import config
import requests
from urllib import parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from api import random_str, generateResponse, url_dict2str, PLACE, VulType, HTTPMETHOD, Type, PluginBase, KB, logger, conf
from lib.helper.diifpage import findDynamicContent, getFilteredPageContent, removeDynamicContent


class Z0SCAN(PluginBase):
    name = "SQLiBool"
    desc = 'Bool SQL Finder'
    
    def __init__(self):
        super().__init__()
        # 初始化序列匹配器，用于比较页面内容的相似度
        self.seqMatcher = difflib.SequenceMatcher(None)
        # 设置页面相似度的上下界
        self.UPPER_RATIO_BOUND = 0.98
        self.LOWER_RATIO_BOUND = 0.02

        # 设置页面相似度的差异容忍度
        self.DIFF_TOLERANCE = 0.05
        # 设置常量相似度阈值
        self.CONSTANT_RATIO = 0.9

        # 设置重试次数
        self.retry = 3
        # 存储动态内容的标记
        self.dynamic = []
    
    def condition(self):
        if 1 in conf.level:
            return True
        return False
    
    def findDynamicContent(self, firstPage, secondPage):
        ret = findDynamicContent(firstPage, secondPage)
        if ret:
            self.dynamic.extend(ret)

    def inject(self, k, v, positon, payload_false, payload_true):
        is_inject = False
        payload = self.insertPayload(k, v, positon, payload_false)
        r2 = self.req(positon, payload)
        payload = self.insertPayload(k, v, positon, payload_true)  
        r = self.req(positon, payload)
        
        truePage = removeDynamicContent(r.text, self.dynamic)
        falsePage = removeDynamicContent(r2.text, self.dynamic)
        try:
            self.seqMatcher.set_seq1(self.resp_str)
            self.seqMatcher.set_seq2(falsePage)
            ratio_false = round(self.seqMatcher.quick_ratio(), 3)
            if ratio_false == 1.0:
                return False
        except (MemoryError, OverflowError):
            return False
        if truePage == falsePage:
            return False

        try:
            self.seqMatcher.set_seq1(self.resp_str or "")
            self.seqMatcher.set_seq2(truePage or "")
            ratio_true = round(self.seqMatcher.quick_ratio(), 3)
        except (MemoryError, OverflowError):
            return False
        if ratio_true > self.UPPER_RATIO_BOUND and abs(ratio_true - ratio_false) > self.DIFF_TOLERANCE:
            if ratio_false <= self.UPPER_RATIO_BOUND:
                is_inject = True
        if not is_inject and ratio_true > 0.68 and ratio_true > ratio_false:
            originalSet = set(getFilteredPageContent(self.resp_str).split("\n"))
            trueSet = set(getFilteredPageContent(truePage).split("\n"))
            falseSet = set(getFilteredPageContent(falsePage).split("\n"))

            if len(originalSet - trueSet) <= 2 and trueSet != falseSet:
                candidates = trueSet - falseSet
                if len(candidates) > 0:
                    is_inject = True
        if is_inject:
            ret = []
            ret.append({
                "request": r.reqinfo,
                "response": generateResponse(r),
                "key": k,
                "payload": payload_true,
                "position": positon,
                "desc": "发送True请求包与原网页相似度:{}".format(ratio_true)
            })
            ret.append({
                "request": r2.reqinfo,
                "response": generateResponse(r2),
                "key": k,
                "payload": payload_false,
                "position": positon,
                "desc": "发送False请求包与原网页相似度:{}".format(ratio_false)
            })
            return ret
        else:
            return False

    def audit(self):
        if not self.condition():
            return
        count = 0
        ratio = 0
        self.resp_str = self.response.text
        # 处理动态变动以减少误差
        while ratio <= 0.98:
            if count > self.retry:
                return
            if self.requests.method == HTTPMETHOD.POST:
                r = requests.post(self.requests.url, data=self.requests.data, headers=self.requests.headers)
            else:
                r = requests.get(self.requests.url, headers=self.requests.headers)
            html = removeDynamicContent(r.text, self.dynamic)
            self.resp_str = removeDynamicContent(self.resp_str, self.dynamic)
            try:
                self.seqMatcher.set_seq1(self.resp_str)
                self.seqMatcher.set_seq2(html)
                ratio = round(self.seqMatcher.quick_ratio(), 3)
            except MemoryError:
                return
            self.findDynamicContent(self.resp_str, html)
            count += 1
            
        iterdatas = self.generateItemdatas()
        with ThreadPoolExecutor(max_workers=None) as executor:
            futures = [
                executor.submit(self.process, _) for _ in iterdatas
            ]
            try:
                for future in as_completed(futures):
                    future.result()
            except Exception as e:
                executor.shutdown(False)
                logger.error(e, origin="SQLiBool")
                # raise
                    
    def process(self, _):
        k, v, position = _
        # ["true", "false"]
        # 井号相比于--+更为适用
        # 不一定动态Payload才是最好的，静态也可以很强势
        int_payloads_yunshuan = [
            # 运算符（减法）
            ["-0", "-10000"],
            ["'-'0", "'-'10000"],
            ['"-"0', '"-"10000']
        ]
        if not KB["WAFSTATE"]:
            int_payloads_luoji = [
                # 逻辑符（AND）
                [" AND True", " AND False"],
                ["'AND'True", "'AND'False"],
                ['"AND"True', '"AND"False'],
                ["') AND True#", "') AND False#"],
                ['") AND True#', '") AND False#']
            ]
            str_payloads_luoji = [
                # 逻辑符（AND）
                ["'AND'True", "'AND'False"],
                ['"AND"True', '"AND"False'],
                ["') AND True#", "') AND False#"],
                ['") AND True#', '") AND False#']
            ]
            str_payloads_yunshuan = []
        else:
            # xor可能会被or拦截规则误伤
            # 相比于xor，特殊字符^拦截概率要更低
            int_payloads_luoji = [
                # 逻辑符（异或）
                ["^True", "^False"],
                ["'^'True", "'^'False"],
                ['"^"True', '"^"False']
            ]
            str_payloads_luoji = [
                # 逻辑符（异或）
                ["'^'True", "'^'False"],
                ['"^"True', '"^"False']
            ]
            str_payloads_yunshuan = [
                # 运算符（减法）
                ["'-'0", "'-'10000"],
                ['"-"0', '"-"10000']
            ]
        if str(v).isdigit():
            _payloads = int_payloads_yunshuan + int_payloads_luoji
        else:
            _payloads = str_payloads_yunshuan + str_payloads_luoji
        for payload in _payloads:
            payload_true, payload_false = payload
            ret1 = self.inject(k, v, position, payload_false, payload_true)
            if ret1:
                payload_true, payload_false = payload
                ret2 = self.inject(k, v, position, payload_false, payload_true)
                if ret2:
                    result = self.new_result()
                    result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SQLI, position, param=k, payload=payload)
                    for values in ret1:
                        result.add_detail("The First Bool Injection Test", values["request"], values["response"], values["desc"])
                    for values in ret2:
                        result.add_detail("The Second Bool Injection Test", values["request"], values["response"], values["desc"])
                    self.success(result)
                    return True