#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:  checkwaf
from lib.core.data import conf, logger, KB
from re import search, I, compile, error
from lib.core.db import insertdb, selectdb
from config import HEURiITIC_WAF_CHECK
import os, requests, sys
from urllib.parse import urlencode
import random
import string
import difflib

match = [
    r'wts/[0-9\.]+?', r'Airee', r'qianxin\-waf', r'YUNDUN'
]

def CheckWaf(self):
    KB["limit"] = True
    condition = "HOSTNAME={}".format(self.requests.hostname)
    history = selectdb("WAFHISTORY", "STATE", condition=condition)
    if history:
        if bool(history[0]):
            KB["WAFSTATE"] = True
            return
    
    _ = False
    if 'server' in self.requests.headers.keys():
        for _ in match:
            if search(_, self.requests.headers["server"], I):
                deal(self.requests.hostname, True)
                return
    
    if HEURiITIC_WAF_CHECK:
        rand_param = '?' + ''.join(random.choices(string.ascii_lowercase, k=6))
        payload = "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"
        try:
            r1 = requests.get(self.requests.netloc, timeout=conf.timeout)
            r2 = requests.get(self.requests.netloc + rand_param + urlencode(payload), timeout=conf.timeout)
        # 超时与连接问题很可能产生于WAF
        except (TimeoutError, ConnectionError, Exception) as e:
            deal(self.requests.hostname, True)
            return
        # 页面相似度判断
        similarity = difflib.SequenceMatcher(r1, r2).ratio()
        if similarity < 0.5:
            deal(self.requests.hostname, True)
            return
        else:
            deal(self.requests.hostname, False)
    else:
        KB["WAFSTATE"] = False
        return

def deal(hostname, state):
    if state:
        KB.lock.acquire()
        logger.warning(f"| <\033[36m{hostname}\033[0m> Previous heuristics detected that the target is protected by some kind of WAF/IPS")
        KB.lock.release()
        KB["WAFSTATE"] = True
        cv = {"HOSTNAME": hostname,
              "STATE": True}
        insertdb("WAFHISTORY", cv)
        return
    else:
        KB["WAFSTATE"] = False
        cv = {"HOSTNAME": hostname, 
              "STATE": False}
        insertdb("WAFHISTORY", cv)
        return