#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/30
# JiuZero 2025/7/29

import difflib
import requests

from api import generateResponse, VulType, HTTPMETHOD, Type, PluginBase, conf, Threads, KB
from lib.helper.diifpage import findDynamicContent, getFilteredPageContent, removeDynamicContent
from helper.paramanalyzer import VulnDetector


class Z0SCAN(PluginBase):
    name = "sqli-bool"
    desc = 'SQL Boolean-based Blind Injection'
    version = "2025.7.29"
    risk = 2
    
    def __init__(self):
        super().__init__()
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
        # 布尔盲注概率计算
        self.MIN_DIFF_RATIO = 0.1  # 最小差异比率
    
    def calculate_boolean_probability(self, original_page, true_page, false_page):
        # 计算原始页面与真/假页面的相似度
        self.seqMatcher.set_seq1(original_page)
        self.seqMatcher.set_seq2(true_page)
        true_ratio = round(self.seqMatcher.quick_ratio(), 3)
        
        self.seqMatcher.set_seq1(original_page)
        self.seqMatcher.set_seq2(false_page)
        false_ratio = round(self.seqMatcher.quick_ratio(), 3)
        
        # 计算真/假页面之间的差异度
        self.seqMatcher.set_seq1(true_page)
        self.seqMatcher.set_seq2(false_page)
        diff_ratio = 1.0 - round(self.seqMatcher.quick_ratio(), 3)

        probability = 0.0
        if true_ratio > self.UPPER_RATIO_BOUND and false_ratio < self.UPPER_RATIO_BOUND:
            probability = 0.8 + min(diff_ratio, 0.2)
        elif diff_ratio > self.MIN_DIFF_RATIO:
            probability = 0.6 + min(diff_ratio * 0.5, 0.4)
        else:
            original_lines = set(getFilteredPageContent(original_page).split("\n"))
            true_lines = set(getFilteredPageContent(true_page).split("\n"))
            false_lines = set(getFilteredPageContent(false_page).split("\n"))
            
            true_diff = len(true_lines - original_lines)
            false_diff = len(false_lines - original_lines)
            
            if true_diff <= 2 and false_diff > 2:
                probability = 0.7
            elif true_diff != false_diff:
                probability = 0.5 + (abs(true_diff - false_diff) * 0.1)
        return max(0.0, min(1.0, probability))
    
    def findDynamicContent(self, firstPage, secondPage):
        ret = findDynamicContent(firstPage, secondPage)
        if ret:
            self.dynamic.extend(ret)

    def inject(self, k, v, position, payload_false, payload_true):
        is_inject = False
        payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": payload_false
                })
        r2 = self.req(position, payload)
        payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": payload_true
                })
        r = self.req(position, payload)
        
        truePage = removeDynamicContent(r.text, self.dynamic)
        falsePage = removeDynamicContent(r2.text, self.dynamic)
        originalPage = removeDynamicContent(self.resp_str, self.dynamic)
        
        # 计算布尔盲注概率
        self.probability = self.calculate_boolean_probability(originalPage, truePage, falsePage)
        
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
            
        # 使用概率值作为判断依据
        if ratio_true > self.UPPER_RATIO_BOUND and abs(ratio_true - ratio_false) > self.DIFF_TOLERANCE:
            if ratio_false <= self.UPPER_RATIO_BOUND:
                is_inject = True
        elif not is_inject and ratio_true > 0.68 and ratio_true > ratio_false:
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
                "position": position,
                "desc": f"The similarity between the true request packet and the original web page:{ratio_true}, Probability: {self.probability:.2f}"
            })
            ret.append({
                "request": r2.reqinfo,
                "response": generateResponse(r2),
                "key": k,
                "payload": payload_false,
                "position": position,
                "desc": f"The similarity between the False request packet and the original web page:{ratio_false}, Probability: {self.probability:.2f}"
            })
            return ret
        else:
            return False

    def audit(self):
        if not (self.risk in conf.risk or conf.level != 0):
            return
        count = 0
        ratio = 0
        self.resp_str = self.response.text
        # 处理动态变动以减少误差
        while ratio <= 0.98:
            if count > self.retry:
                return
            if self.requests.method == HTTPMETHOD.POST:
                r = requests.post(self.requests.url, data=self.requests.body, headers=self.requests.headers)
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
        z0thread = Threads(name="sqli-bool")
        z0thread.submit(self.process, iterdatas)
    
    def process(self, _):
        k, v, position = _
        if not VulnDetector(self.requests.url).is_sql_injection(k, v):
            return
        # ["true", "false"]
        payloads = [
            ["'-'0", "'-'10000"],
            ['"-"0', '"-"10000'], 
            ["'AND'True", "'AND'False"],
            ['"AND"True', '"AND"False'],
            ["') AND True#", "') AND False#"],
            ['") AND True#', '") AND False#'], 
        ]
        if conf.level == 3:
            payloads += [
                ["''AND''True", "''AND''False"],
                ['""AND True#""', '""AND False#""'],
            ]
        if str(v).isdigit():
            int_payloads = [
                ["-0", "-10000"],
                ["/1", "/0"],
                [" AND True", " AND False"],
                [" AND True#", " AND False#"],
            ]
            payloads = int_payloads + payloads
        if self.fingerprints.waf:
            if str(v).isdigit():
                payloads = [
                    ["-0", "-10000"],
                ]
                if conf.level >= 2:
                    payloads += [["/1", "/0"],]
                if conf.level == 3:
                    payloads += [
                        ["'/'1", "'/'0"], 
                        ['"/"1', '"/"0'],
                    ]
            else:
                return
        for payload in payloads:
            payload_true, payload_false = payload
            ret1 = self.inject(k, v, position, payload_false, payload_true)
            if ret1:
                payload_true, payload_false = payload
                ret2 = self.inject(k, v, position, payload_false, payload_true)
                if ret2:
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.SQLI, 
                        "show": {
                            "Position": f"{position} >> {k}",
                            "Probability": f"{self.probability:.2f}", 
                            "Payload": payload,
                        }
                    })
                    for values in ret1:
                        result.step("Request1", {
                            "position": position,
                            "request": values["request"], 
                            "response": values["response"], 
                            "desc": values["desc"],
                        })
                    for values in ret2:
                        result.step("Request2", {
                            "position": position, 
                            "request": values["request"], 
                            "response": values["response"], 
                            "desc": values["desc"],
                        })
                    self.success(result)
                    return True