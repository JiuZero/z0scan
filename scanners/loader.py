#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from copy import deepcopy
import requests, threading, sqlite3, re, os
from lib.controller.controller import task_push
from lib.core.common import get_parent_paths, get_links
from lib.core.data import conf, KB, path
from lib.core.log import logger, colors
from lib.core.waf import detector
from lib.core.enums import HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from helper.paramanalyzer import VulnDetector
from lib.core.portscan import ScanPort
from bs4 import BeautifulSoup as BS

rtitle = re.compile(r'title="(.*)"')
rheader = re.compile(r'header="(.*)"')
rbody = re.compile(r'body="(.*)"')
rbracket = re.compile(r'\((.*)\)')

def check(_id):
    with sqlite3.connect(os.path.join(path.data, 'cmsfinger.db')) as conn:
        cursor = conn.cursor()
        result = cursor.execute('SELECT name, keys FROM `tide` WHERE id=\'{}\''.format(_id))
        for row in result:
            return row[0], row[1]

def count():
    with sqlite3.connect(os.path.join(path.data, 'cmsfinger.db')) as conn:
        cursor = conn.cursor()
        result = cursor.execute('SELECT COUNT(id) FROM `tide`')
        for row in result:
            return row[0]

# 欺骗 in 操作
class CheatIn:
    def __contains__(self, item):
        return True
    
class Z0SCAN(PluginBase):
    name = 'loader'
    desc = 'plugin loader'
    
    def check_rule(self, key, header, body, title):
        """指纹识别"""
        try:
            if 'title="' in key:
                if re.findall(rtitle, key)[0].lower() in title.lower():
                    return True
            elif 'body="' in key:
                if re.findall(rbody, key)[0] in body: return True
            else:
                if re.findall(rheader, key)[0] in header: return True
        except Exception as e:
            pass

    def handle(self, _id, header, body, title):
        """取出数据库的key进行匹配"""
        self.finger = []
        name, key = check(_id)
        # 满足一个条件即可的情况
        if '||' in key and '&&' not in key and '(' not in key:
            for rule in key.split('||'):
                if self.check_rule(rule, header, body, title):
                    self.finger.append(name)
                    # print '%s[+] %s   %s%s' % (G, self.target, name, W)
                    break
        # 只有一个条件的情况
        elif '||' not in key and '&&' not in key and '(' not in key:
            if self.check_rule(key, header, body, title):
                self.finger.append(name)
                # print '%s[+] %s   %s%s' % (G, self.target, name, W)
        # 需要同时满足条件的情况
        elif '&&' in key and '||' not in key and '(' not in key:
            num = 0
            for rule in key.split('&&'):
                if self.check_rule(rule, header, body, title):
                    num += 1
            if num == len(key.split('&&')):
                self.finger.append(name)
                # print '%s[+] %s   %s%s' % (G, self.target, name, W)
        else:
            # 与条件下存在并条件: 1||2||(3&&4)
            if '&&' in re.findall(rbracket, key)[0]:
                for rule in key.split('||'):
                    if '&&' in rule:
                        num = 0
                        for _rule in rule.split('&&'):
                            if self.check_rule(_rule, header, body, title):
                                num += 1
                        if num == len(rule.split('&&')):
                            self.finger.append(name)
                            # print '%s[+] %s   %s%s' % (G, self.target, name, W)
                            break
                    else:
                        if self.check_rule(rule, header, body, title):
                            self.finger.append(name)
                            # print '%s[+] %s   %s%s' % (G, self.target, name, W)
                            break
            else:
                # 并条件下存在与条件： 1&&2&&(3||4)
                for rule in key.split('&&'):
                    num = 0
                    if '||' in rule:
                        for _rule in rule.split('||'):
                            if self.check_rule(_rule, title, body, header):
                                num += 1
                                break
                    else:
                        if self.check_rule(rule, title, body, header):
                            num += 1
                if num == len(key.split('&&')):
                    self.finger.append(name)
                    # print '%s[+] %s   %s%s' % (G, self.target, name, W)
    
    def get_info(self):
        try:
            title = BS(self.response.text, 'lxml').title.text.strip()
            return str(self.response.headers), self.response.text, title.strip('\n')
        except:
            return str(self.response.headers), self.response.text, ''
    
    def audit(self):
        headers = deepcopy(self.requests.headers)
        url = deepcopy(self.requests.url)
        hostname = deepcopy(self.requests.hostname)
        
        # Waf检测
        if not conf.ignore_waf:
            while self.requests.hostname in KB.waf_detecting:
                pass
            KB.waf_detecting.append(self.requests.hostname)
            detector(self)
            KB.waf_detecting.remove(self.requests.hostname)
            if self.fingerprints.waf == "None":
                self.fingerprints.waf = False
        else:
            self.fingerprints.waf = False

        lower_headers = {k.lower(): v.lower() for k, v in self.response.headers.items()}
        for name, values in KB["fingerprint"].items():
            if not getattr(self.fingerprints, name):
                if conf.ignore_fingerprint:
                    _result = CheatIn()
                    setattr(self.fingerprints, name, _result)
                else:
                    _result = []
                    for mod in values:
                        m = mod.fingerprint(self.requests.suffix.lower(), lower_headers, self.response.text)
                        if isinstance(m, str):
                            _result.append(m)
                    if _result:
                        setattr(self.fingerprints, name, _result)

        # PerDomain
        domain = deepcopy(self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port)) # 保留端口去重
        if KB["spiderset"].add(domain, 'PerDomain'):
            try:
                header, body, title = self.get_info()
                for _id in range(1, int(count()),1):
                    try:
                        self.handle(_id, header, body, title)
                    except Exception as e:
                        pass
            except Exception as e:
                logger.error(e, origin="cmsfinger")
            if self.finger != []:
                logger.info(f"<{colors.m}{self.requests.hostname}{colors.e}> Banner: {self.finger}")
                if conf.ignore_fingerprint:
                    setattr(self.fingerprints, "cms", CheatIn())
                else:
                    setattr(self.fingerprints, "cms", self.finger)
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push('PerDomain', fake_req, fake_resp, self.fingerprints)
            
        # PerPage
        if KB["spiderset"].add(url, 'PerPage'):
            task_push('PerPage', self.requests, self.response, self.fingerprints)
            iterdatas = self.generateItemdatas()
            for _ in iterdatas:
                k, v, position = _
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_sql_injection(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_file_access(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_redirect(k, v)
                VulnDetector(self.requests.url, conf.hidden_vul_reminder).is_ssrf(k, v)
            
        # PerDir
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            """
            # 由插件内部决策
            if parent_url.count("/") > int(conf.max_dir) + 2:
                return
            """
            if not KB["spiderset"].add(parent_url, 'get_link_directory'):
                continue
            if KB["spiderset"].add(parent_url, 'PerDir'):
                req = requests.get(parent_url, headers=headers, allow_redirects=False)
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerDir', fake_req, fake_resp, self.fingerprints)
        
        # PerHost
        hostname = deepcopy(self.requests.hostname) # 无端口去重
        if KB["spiderset"].add(hostname, 'PerHost'):
            ScanPort(hostname).run()