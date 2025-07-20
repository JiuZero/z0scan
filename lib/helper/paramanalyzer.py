#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/20

import re

def is_sql_injection(key, value):
    non_sql_key_patterns = [
        r'^(theme|color|font|lang|ui|sidebar)',  # 前端UI（含colorScheme, fontSize等）
        r'(token|session|auth|oauth|sso)',       # 认证相关（含csrfToken, access_token等）
        r'(file|path|dir|upload|download|mime|ext|filename)',  # 文件操作（含filePath, uploadDir等）
        r'(js|css|img|icon|favicon|asset|cdn|static)',  # 静态资源
        r'(user[ _-]agent|referrer|content[ _-]type)',  # HTTP头
        r'(time|date|zone|locale|format|timestamp)',     # 时间/本地化
        r'(api[ _-]?key|recaptcha|secret|nonce)',       # 第三方密钥
        r'(debug|log|trace|verbose|test|mock)',         # 调试日志
    ]

    non_sql_value_patterns = [
        r'^[a-f0-9]{32}$',               # MD5（不区分大小写）
        r'^[a-f0-9]{64}$',               # SHA-256
        r'^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$',  # UUID
        r'^(true|false|null|undefined)$', # 固定字面量
        r'^data:[a-z0-9/+-]+;base64,',   # Base64数据URI
    ]

    # 检查键是否匹配非SQL模式（不区分大小写）
    key_matched = any(
        re.search(pattern, key, re.IGNORECASE) 
        for pattern in non_sql_key_patterns
    )


    # 检查值是否匹配非SQL模式
    value_matched = any(
        re.fullmatch(pattern, value, re.IGNORECASE) 
        for pattern in non_sql_value_patterns
    )

    if key_matched or value_matched:
        return False
    return True