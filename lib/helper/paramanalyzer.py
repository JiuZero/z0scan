#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/22

import re
from lib.core.data import conf
from lib.core.log import logger

class VulnDetector():
    def __init__(self, url, remind=False):
        super().__init__()
        self.remind = remind
        self.url = url
            
    def is_sql_injection(self, key, value):
        """SQL注入检测"""
        safe_keys = [
            r'^(theme|color|font|lang|ui|sidebar)\b',
            r'\b(token|session|auth|oauth|sso)\b',
            r'\b(file|path|dir|upload|download|mime|ext)\b',
            r'\b(js|css|img|icon|favicon|asset|cdn|static)\b',
            r'\b(useragent|referrer|contenttype)\b',
            r'\b(time|date|zone|locale|format|timestamp)\b',
            r'\b(apikey|recaptcha|secret|nonce)\b',
            r'\b(debug|log|trace|verbose|test|mock)\b'
        ]
        
        safe_values = [
            r'^[a-f0-9]{32,64}$',
            r'^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$',
            r'^(true|false|null|undefined)$',
        ]
        if conf.level == 3:
            return True
        key_safe = any(re.search(p, key, re.IGNORECASE) for p in safe_keys)
        value_safe = any(re.fullmatch(p, value, re.IGNORECASE) for p in safe_values)
        if not (key_safe or value_safe):
            if self.remind:
                logger.info(f"Suspected interactive Database: {self.url} => {key}")
            return True
        return False
    
    def is_redirect(self, key, value):
        """重定向检测"""
        redirect_keys = [
            r'^redirect[a-z0-9]*$',
            r'^(url|jump|to|link|domain)[a-z0-9]*$',
            r'^callbackurl$'
        ]
        if (any(re.fullmatch(p, key, re.IGNORECASE) for p in redirect_keys)) or re.match(r'^(http|https|ftp|javascript):', value, re.IGNORECASE):
            if self.remind:
                logger.info(f"Suspected Redirect param: {self.url} => {key}")
            return True
        if conf.level == 3:
            return True
        return False
        
    def is_file_access(self, key, _):
        """文件操作检测"""
        patterns = [
            r'^(file|path|name)[a-z0-9]*$',
            r'^(metainf|webinf)$',
            r'^(topic|attach|download)[a-z0-9]*$'
        ]
        if any(re.fullmatch(p, key, re.IGNORECASE) for p in patterns):
            if self.remind:
                logger.info(f"Suspected File operations: {self.url} => {key}")
            return True
        if conf.level == 3:
            return True
        return False
    
    def is_ssrf(self, key, value):
        """SSRF检测"""
        args = ['open', 'location', 'goto', 'address', 'target', 'wap', 'domain', '3g', 'g', 'go', 'share', 'redir', 'addr', 'u', 'to', 'display']
        ssrf_keys = [
            r'^(url|link|src|source)[a-z0-9]*$',
            r'^(api|service|endpoint)[a-z0-9]*$',
            r'^image(url|uri|src)$'
        ]
        if (any(re.fullmatch(p, key, re.IGNORECASE) for p in ssrf_keys)) or re.search(r'(127\.|192\.168|10\.|172\.(1[6-9]|2\d|3[01]))', value) or key.lower() in args:
            if self.remind:
                logger.info(f"Suspected SSRF param: {self.url} => {key}")
            return True
        if conf.level == 3:
            return True
        return False