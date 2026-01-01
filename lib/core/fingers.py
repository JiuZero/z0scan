#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# JiuZero/z0scan

import sqlite3, os
from bs4 import BeautifulSoup as BS
from lib.core.data import conf, KB, path
from lib.core.log import logger, colors
from lib.core.db import insertdb, selectdb
import requests, random, string, re
from urllib.parse import quote, urlsplit

rpath = re.compile(r'path="(.*)"')
rtitle = re.compile(r'title="(.*)"')
rheader = re.compile(r'header="(.*)"')
rbody = re.compile(r'body="(.*)"')
rbracket = re.compile(r'\((.*)\)')
rpath_regex = re.compile(r'path_regex="(.*)"')
rtitle_regex = re.compile(r'title_regex="(.*)"')
rheader_regex = re.compile(r'header_regex="(.*)"')
rbody_regex = re.compile(r'body_regex="(.*)"')

def Fcount():
    with sqlite3.connect(os.path.join(path.data, 'fingers.db')) as conn:
        cursor = conn.cursor()
        result = cursor.execute('SELECT COUNT(id) FROM `finger`')
        for row in result:
            return row[0]
            
def Wcount():
    with sqlite3.connect(os.path.join(path.data, 'fingers.db')) as conn:
        cursor = conn.cursor()
        result = cursor.execute('SELECT COUNT(id) FROM `waf`')
        for row in result:
            return row[0]

# 为指导Scanners Payloads选择的指纹集
class finger:
    def __init__(self, datas: dict):
        self.finger = []
        self.header = str(datas["headers"])
        self.body = datas["body"]
        self.path = urlsplit(datas["url"]).path
        
    def check(self, _id):
        with sqlite3.connect(os.path.join(path.data, 'fingers.db')) as conn:
            cursor = conn.cursor()
            result = cursor.execute('SELECT name, keys FROM `finger` WHERE id=\'{}\''.format(_id))
            for row in result:
                return row[0], row[1]
                
    def check_rule(self, key):
        try:
            if 'title="' in key:
                pattern = re.findall(rtitle, key)[0]
                if re.search(pattern, self.title, re.IGNORECASE): 
                    return True
            elif 'body="' in key:
                pattern = re.findall(rbody, key)[0]
                if re.search(pattern, self.body): 
                    return True
            elif 'header="' in key:
                pattern = re.findall(rheader, key)[0]
                if re.search(pattern, self.header): 
                    return True
            elif 'path="' in key:
                pattern = re.findall(rpath, key)[0]
                if re.search(pattern, self.path): 
                    return True
            elif 'title_regex="' in key:
                pattern = re.findall(rtitle_regex, key)[0]
                if re.search(pattern, self.title, re.IGNORECASE): 
                    return True
            elif 'body_regex="' in key:
                pattern = re.findall(rbody_regex, key)[0]
                if re.search(pattern, self.body): 
                    return True
            elif 'header_regex="' in key:
                pattern = re.findall(rheader_regex, key)[0]
                if re.search(pattern, self.header): 
                    return True
            elif 'path_regex="' in key:
                pattern = re.findall(rpath_regex, key)[0]
                if re.search(pattern, self.path): 
                    return True
            return False
        except Exception as e:
            # logger.debug(f"正则匹配错误: {e}, 规则: {key}")
            return False

    def handle(self, _id):
        """取出数据库的key进行匹配"""
        name, key = self.check(_id)
        # 满足一个条件即可的情况
        if '||' in key and '&&' not in key and '(' not in key:
            for rule in key.split('||'):
                if self.check_rule(rule):
                    self.finger.append(name)
                    break
        # 只有一个条件的情况
        elif '||' not in key and '&&' not in key and '(' not in key:
            if self.check_rule(key):
                self.finger.append(name)
        # 需要同时满足条件的情况
        elif '&&' in key and '||' not in key and '(' not in key:
            num = 0
            for rule in key.split('&&'):
                if self.check_rule(rule):
                    num += 1
            if num == len(key.split('&&')):
                self.finger.append(name)
        else:
            # 与条件下存在并条件: 1||2||(3&&4)
            if '&&' in re.findall(rbracket, key)[0]:
                for rule in key.split('||'):
                    if '&&' in rule:
                        num = 0
                        for _rule in rule.split('&&'):
                            if self.check_rule(_rule):
                                num += 1
                        if num == len(rule.split('&&')):
                            self.finger.append(name)
                            break
                    else:
                        if self.check_rule(rule):
                            self.finger.append(name)
                            break
            else:
                # 并条件下存在与条件： 1&&2&&(3||4)
                for rule in key.split('&&'):
                    num = 0
                    if '||' in rule:
                        for _rule in rule.split('||'):
                            if self.check_rule(_rule):
                                num += 1
                                break
                    else:
                        if self.check_rule(rule):
                            num += 1
                if num == len(key.split('&&')):
                    self.finger.append(name)
    
    def detector(self):
        try:
            try:
                self.title = BS(self.body, 'lxml').title.text.strip()
            except:
                self.title = ""
            _count = Fcount()
            for _id in range(1, int(_count),1):
                try:
                    self.handle(_id)
                except Exception as e:
                    pass
            return self.finger
        except Exception as e:
            logger.error(e, origin="finger")
            return self.finger


# WAF 指纹集
class waf:
    def __init__(self, datas: dict):
        self.protocol = datas["protocol"]
        self.hostname = datas["hostname"]
        self.port = datas["port"]
        self.raw = datas["raw"]
        self.headers = datas["headers"]
        self.path = urlsplit(datas["url"]).path
        
    def check(self, _id):
        with sqlite3.connect(os.path.join(path.data, 'fingers.db')) as conn:
            cursor = conn.cursor()
            result = cursor.execute('SELECT name, position, regex FROM `waf` WHERE id=\'{}\''.format(_id))
            for row in result:
                return row[0], row[1]
            
    def check_rule(self, key):
        try:
            # 原有的字符串包含匹配
            if 'title="' in key:
                pattern = re.findall(rtitle, key)[0]
                if re.search(pattern, self.title, re.IGNORECASE): 
                    return True
            elif 'body="' in key:
                pattern = re.findall(rbody, key)[0]
                if re.search(pattern, self.body): 
                    return True
            elif 'header="' in key:
                pattern = re.findall(rheader, key)[0]
                if re.search(pattern, self.header): 
                    return True
            elif 'path="' in key:
                pattern = re.findall(rpath, key)[0]
                if re.search(pattern, self.path): 
                    return True
            elif 'title_regex="' in key:
                pattern = re.findall(rtitle_regex, key)[0]
                if re.search(pattern, self.title, re.IGNORECASE): 
                    return True
            elif 'body_regex="' in key:
                pattern = re.findall(rbody_regex, key)[0]
                if re.search(pattern, self.body): 
                    return True
            elif 'header_regex="' in key:
                pattern = re.findall(rheader_regex, key)[0]
                if re.search(pattern, self.header): 
                    return True
            elif 'path_regex="' in key:
                pattern = re.findall(rpath_regex, key)[0]
                if re.search(pattern, self.path): 
                    return True
            return False
        except Exception as e:
            # logger.debug(f"匹配错误: {e}, 规则: {key}")
            return False

    def handle(self, _id):
        """取出数据库的key进行匹配"""
        name, key = self.check(_id)
        # 满足一个条件即可的情况
        if '||' in key and '&&' not in key and '(' not in key:
            for rule in key.split('||'):
                if self.check_rule(rule):
                    return name
        # 只有一个条件的情况
        elif '||' not in key and '&&' not in key and '(' not in key:
            if self.check_rule(key):
                return name
        # 需要同时满足条件的情况
        elif '&&' in key and '||' not in key and '(' not in key:
            num = 0
            for rule in key.split('&&'):
                if self.check_rule(rule):
                    num += 1
            if num == len(key.split('&&')):
                return name
        else:
            # 与条件下存在并条件: 1||2||(3&&4)
            if '&&' in re.findall(rbracket, key)[0]:
                for rule in key.split('||'):
                    if '&&' in rule:
                        num = 0
                        for _rule in rule.split('&&'):
                            if self.check_rule(_rule):
                                num += 1
                        if num == len(rule.split('&&')):
                            return name
                    else:
                        if self.check_rule(rule):
                            return name
            else:
                # 并条件下存在与条件： 1&&2&&(3||4)
                for rule in key.split('&&'):
                    num = 0
                    if '||' in rule:
                        for _rule in rule.split('||'):
                            if self.check_rule(_rule):
                                num += 1
                                break
                    else:
                        if self.check_rule(rule):
                            num += 1
                if num == len(key.split('&&')):
                    return name
        return False
                    
    def detector(self):
        where = "hostname='{}'".format(self.hostname)
        history = selectdb("info", "waf", where=where)
        
        if history == "NoWaf":
            return False
        elif not history is None:
            return str(history[0])
        
        rand_param = '/?' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '='
        payload = "UNION ALL SELECT 1,'<script>alert(\"XSS\")</script>' FROM information_schema WHERE --/**/ EXEC xp_cmdshell('cat ../../../etc/passwd')#"
        try:
            r = requests.get(self.protocol + "://" + self.hostname + ":" + str(self.port) + "/" + rand_param + quote(payload))
            # 1. 匹配指纹
            for _id in range(1, int(Wcount()),1):
                try:
                    name = self.handle(_id)
                    if name:
                        logger.warning("{}{}{} Protected by {}".format(colors.m, self.hostname, colors.e, name))
                        cv = {"hostname": self.hostname, 
                              "waf": name}
                        insertdb("info", cv)
                        return name
                except Exception as e:
                    pass
                                
            # 2. 非正常响应码
            # 405 - Anquanbao, 493 - 360, 403 - AWS WAF
            # 400 - ChinaCache (ChinaCache Networks), EdgeCast Web Application Firewall (Verizon)
            if r.status_code in (493, 405, 403, 400) or r.status_code >= 500:
                logger.warning("{}{}{} Abnormal response ({}), possible WAF detected".format(colors.m, self.hostname, colors.e, r.status_code))
                cv = {"hostname": self.hostname, 
                      "waf": "UNKNOW"}
                insertdb("info", cv)
                return "UNKNOW"
            
            # 似乎没有WAF？
            cv = {"hostname": self.hostname, 
                  "waf": "NoWaf"}
            insertdb("info", cv)
            return False
            
        # 3. 超时与连接问题很可能产生于WAF
        except (TimeoutError, ConnectionError) as e:
            logger.warning("{}{}{} An error occurred during the request, possible WAF detected".format(colors.m, self.hostname, colors.e))
            cv = {"hostname": self.hostname,
                  "waf": "UNKNOW"}
            insertdb("info", cv)
            return "UNKNOW"
        except Exception as e:
            logger.error(e, origin="waf")
            cv = {"hostname": self.hostname,
                  "waf": "UNKNOW"}
            insertdb("info", cv)
            return "UNKNOW"