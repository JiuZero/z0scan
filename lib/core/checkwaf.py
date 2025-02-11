#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:  checkwaf
from lib.core.data import conf, logger, KB
from re import search, I, compile, error
from config import HEURiITIC_WAF_CHECK
import os, requests, sys
from urllib.parse import urlencode
import random
import string
import difflib

# Server
keys_1 = [
    r'wts/[0-9\.]+?', r'Airee', r'qianxin\-waf', r'YUNDUN'
]

def CheckWaf(self):
    if conf.ignore_waf:
        return
    KB["limit"] = True
    if self.requests.hostname in KB["WafHistory"]:
        KB["WafState"] = True
        return
    if not self.requests.hostname in KB["WafHistory"] and self.requests.hostname in KB["CheckHistory"]:
        KB["WafState"] = False
        return
    _ = False
    if 'server' in self.requests.headers.keys():
        for _ in keys_1:
            if search(_, self.requests.headers["server"], I):
                WriteIn(self.requests.hostname)
                return
            else:
                KB["WafState"] = False
                KB["CheckHistory"].append(self.requests.hostname)
    if HEURiITIC_WAF_CHECK:
        # Reference: http://seclists.org/nmap-dev/2011/q2/att-1005/http-waf-detect.nse
        rand_param = '?' + ''.join(random.choices(string.ascii_lowercase, k=6))
        payload = "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"
        try:
            r1 = requests.get(self.requests.netloc, timeout = conf.timeout)
            r2 = requests.get(self.requests.netloc + rand_param + urlencode(payload), timeout = conf.timeout)
        except (TimeoutError, ConnectionError, Exception) as e:
            WriteIn(self.requests.hostname)
            return
        similarity = difflib.SequenceMatcher(r1, r2).ratio()
        if similarity < 0.5:
            WriteIn(self.requests.hostname)
            return
        else:
            KB["WafState"] = False
            KB["CheckHistory"].append(self.requests.hostname)
            return


def WriteIn(hostname):
    logger.warning("[%s] Previous heuristics detected that the target is protected by some kind of WAF/IPS" % hostname)
    KB["WafState"] = True
    KB["CheckHistory"].append(hostname)
    KB["WafHistory"].append(hostname)
    try:
        with open(file_path, 'a', encoding='utf-8') as file:  # 使用 'a' 模式以追加方式打开文件
            file.write(hostname + "\n")  # 写入一行文字，包括换行符
    except IOError as e:
        logger.error(f"写入文件时发生错误: {e}")
        exit


def initWafCheck(root):
    if conf.ignore_waf:
        return
    global file_path
    file_path = os.path.join(root, 'data', 'hadwaf.history')
    # 检查文件是否存在，如果不存在则创建空文件
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as file:
            logger.warning(f"File {file_path} does not exist, an empty file has been created.")
            logger.warning("QUIT.")
            sys.exit(0)
        # 由于文件是新创建的，不需要再读取
    else:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                KB["CheckHistory"] = KB["WafHistory"] = [line.strip() for line in file]
        except Exception as e:
            logger.error(f"读取文件时发生错误: {e}")
            exit