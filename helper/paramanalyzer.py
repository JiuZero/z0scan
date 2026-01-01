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
            return True
        return False
        
    def is_file_access(self, key, _):
        """文件操作检测"""
        patterns = [
            r'^(file|path|name)[a-z0-9]*$',
            r'^(metainf|webinf|page)$',
            r'^(topic|attach|download)[a-z0-9]*$'
        ]
        if any(re.fullmatch(p, key, re.IGNORECASE) for p in patterns):
            if self.remind:
                logger.info(f"FileAccessParam: {self.url} → {key}")
            return True
        if conf.level == 3:
            return True
        return False
    
    def is_ssrf_redir(self, key, value):
        """SSRF/Redir检测"""
        keys = [
            r'^(url|uri|jump|to|link|domain|addr|source|go|redir|src)[a-z0-9]*$',
            r'^(api|service|endpoint|callback|return)[a-z0-9]*$',
            r'^image(url|uri|src)$', 
            r'^img(url|uri|src)$'
        ]
        args = [
            'host', 'ip', 'target', 'site',
            'website', 'web', 'src', 'dest', 'destination', 
            'webhook', 'proxy', 'fetch', 'resource', 'feed', 
            'location', 'remote', 'forward', 'next', 'continue', 
            'continue_url', 'next_url', 'request', 
            'open', 'target', 
            'wap', 'domain', '3g', 'g', 'share', 
            'u', 'to', 'display'
            "oauth_callback", "ref_url", "text", "content",
            "download", "windows", "data", "reference", "site", "html",
        ]
        if re.search(r'(127\.|192\.168|10\.|172\.(1[6-9]|2\d|3[01]))', value) or key.lower() in args or re.match(r'^(http|https|ftp|javascript):', value, re.IGNORECASE):
            if self.remind:
                logger.info(f"SSRF/RedirParam: {self.url} → {key}")
            return True
        if conf.level == 3:
            return True
        return False