#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4

import string
from urllib.parse import urlparse

import pyjsparser
import requests
import json
import re
from copy import deepcopy
from pyjsparser import parse

from api import random_str, VulType, PLACE, Type, PluginBase, conf, POST_HINT
from lib.helper.helper_sensitive import sensitive_bankcard, sensitive_idcard, sensitive_phone, sensitive_email
from lib.helper.jscontext import analyse_Literal


class Z0SCAN(PluginBase):
    name = "sensi-jsonp"
    desc = 'JSONP Sensitive Finder'
    version = "2025.3.4"
    risk = 1
    
    def jsonp_load(self, jsonp):
        match = re.search(r'^[^(]*?\((.*)\)[^)]*$', jsonp)
        if match is None:
            return None
        json_text = match.group(1)
        if not json_text:
            return None
        try:
            arr = json.loads(json_text)
        except:
            return None
        return str(arr)

    def info_search(self, text) -> dict:
        '''
        从一段文本中搜索敏感信息
        :param text:
        :return:
        '''
        sensitive_params = [sensitive_bankcard, sensitive_idcard, sensitive_phone, sensitive_email]
        sensitive_list = ['username', 'memberid', 'nickname', 'loginid', 'mobilephone', 'userid', 'passportid',
                          'profile', 'loginname', 'loginid',
                          'email', 'realname', 'birthday', 'sex', 'ip']

        for func in sensitive_params:
            ret = func(text)
            if ret:
                return ret
        for item in sensitive_list:
            if item.lower() == text.lower():
                return {"type": "keyword", "content": item}

    def check_sentive_content(self, resp: str) -> set:
        script = resp.strip()
        if not script:
            return set()
        if script[0] == "{":
            script = "d=" + script
        try:
            nodes = parse(script)["body"]
        except pyjsparser.pyjsparserdata.JsSyntaxError as e:
            return set()
        literals = analyse_Literal(nodes)
        result = set()
        for item in literals:
            v = self.info_search(item)
            if v:
                result.add(v["content"])
        return result

    def audit(self):
        if not (1 in conf.risk or self.requests.post_hint == POST_HINT.JSON):
            return
        callbaks = ["callback", "cb", "json"]
        params = deepcopy(self.requests.params)
        isBreak = True
        for p in params.keys():
            if p.lower() in callbaks:
                isBreak = False
                break
        if isBreak:
            return
        result = self.check_sentive_content(self.response.text)
        if not result:
            return
        p = urlparse(self.requests.url)
        fake_domain = "{}://{}".format(p.scheme, p.netloc) + random_str(4,string.ascii_lowercase + string.digits) + ".com/"
        headers = deepcopy(self.requests.headers)
        headers["Referer"] = fake_domain
        req = requests.get(self.requests.url, headers=headers)
        result2 = self.check_sentive_content(req.text)
        if not result2:
            return
        result = self.generate_result()
        result.main({
            "type": Type.REQUEST, 
            "url": req.url, 
            "vultype": VulType.SENSITIVE, 
            "show": {
                "Msg": "{}".format(repr(result2))
                }
            })
        result.step("Request1", {
            "request": self.requests.raw, 
            "response": self.response.raw, 
            "desc": "{}".format(repr(result2))
            })
        self.success(result)
        return