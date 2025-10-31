#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# JiuZero  2025/3/25

from lib.core.data import conf, KB
from lib.core.log import logger, colors
from lib.core.db import insertdb, selectdb
from helper.waffingers import fingers
import requests, random, string, re
from urllib.parse import quote

def detector(self):
    where = "hostname='{}'".format(self.requests.hostname)
    history = selectdb("info", "waf", where=where)
    
    if history == "NoWaf":
        self.fingerprints.waf = False
        return
    elif not history is None:
        self.fingerprints.waf = str(history[0])
        return
    
    rand_param = '/?' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '='
    payload = "UNION ALL SELECT 1,'<script>alert(\"XSS\")</script>' FROM information_schema WHERE --/**/ EXEC xp_cmdshell('cat ../../../etc/passwd')#"
    try:
        r = requests.get(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port) + "/" + rand_param + quote(payload))
        # 1. 匹配指纹
        # Reference: https://github.com/al0ne/Vxscan
        for i in fingers:
            name, position, regex = i.split('|')
            if position == "text":
                if re.search(regex, str(self.requests.raw)):
                    logger.warning("<{}{}{}> Protected by {}".format(colors.m, self.requests.hostname, colors.e, name))
                    self.fingerprints.waf = name
                    return
            else:
                if self.requests.headers is not None:
                    headers = {k.lower(): v for k, v in self.requests.headers.items()}
                    if headers.get(position) is not None:
                        if re.search(regex, headers.get(position).lower()) is not None:
                            logger.warning("<{}{}{}> Protected by {}".format(colors.m, self.requests.hostname, colors.e, name))
                            self.fingerprints.waf = name
                            return
        # 2. 非正常响应码
        if r.status_code in (404, 403, 503) or r.status_code >= 500:
            logger.warning("<{}{}{}> Abnormal response (HTTP {}), possible WAF detected".format(colors.m, self.requests.hostname, colors.e, r.status_code))
            self.fingerprints.waf = "UNKNOW"
            cv = {"hostname": self.requests.hostname,"waf": "UNKNOW"}
            insertdb("info", cv)
            return
        '''
        # 3. 关键字符
        keys = ['攻击行为', '创宇盾', '拦截提示', '非法', '安全威胁', '防火墙', '黑客', '不合法', "Illegal operation"]
        '''
        cv = {"hostname": self.requests.hostname,"waf": "NoWaf"}
        insertdb("info", cv)
        self.fingerprints.waf = False
        return
        
    # 超时与连接问题很可能产生于WAF
    except (TimeoutError, ConnectionError, Exception) as e:
        logger.warning("<{}{}{}> An error occurred during the request, possible WAF detected".format(colors.m, self.requests.hostname, colors.e))
        self.fingerprints.waf = "UNKNOW"
        cv = {"hostname": self.requests.hostname,
              "waf": "UNKNOW"}
        insertdb("info", cv)
        return