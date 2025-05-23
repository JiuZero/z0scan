#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/3/31
# JiuZero 2025/5/7

# 设定注入的数据所处位置
class PLACE:
    PARAM = "PARAM"
    DATA = "DATA"
    URL = "URL"
    COOKIE = "COOKIE"
    HEADER = "HEADER"

# 请求方法
class HTTPMETHOD(object):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    TRACE = "TRACE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    PATCH = "PATCH"

# POST请求的数据传递形式
class POST_HINT(object):
    NORMAL = "NORMAL"
    SOAP = "SOAP"
    JSON = "JSON"
    JSON_LIKE = "JSON-like"
    MULTIPART = "MULTIPART"
    XML = "XML (generic)"
    ARRAY_LIKE = "Array-like"

# 插件扫描方式
class Type(object):
    ANALYZE = "ANALYZE"#被动分析发现
    REQUEST = "REQUEST"#主动请求发现

class VulType(object):
    # 命令注入漏洞
    CMD_INNJECTION = "CMD_INNJECTION"
    # 代码注入漏洞
    CODE_INJECTION = "CODE_INJECTION"
    # 跨站脚本攻击
    XSS = "XSS"
    # SQL注入漏洞
    SQLI = "SQLI"
    # 路径遍历漏洞
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    # XML外部实体注入
    XXE = "XXE"
    # 服务器端请求伪造
    SSRF = "SSRF"
    # CSRF
    CSRF = "CSRF"
    # 重定向漏洞
    REDIRECT = "REDIRECT"
    # 弱口令
    WEAK_PASSWORD = "WEAK_PASSWORD"
    # 换行注入
    CRLF = "CRLF"
    # 敏感信息泄露漏洞
    SENSITIVE = "SENSITIVE"
    # 服务器端模板注入
    SSTI = 'SSTI'
    # 未授权访问
    UNAUTH = 'UNAUTH'
    # 文件上传
    FILEUPLOAD = 'FILEUPLOAD'
    # CORS漏洞
    CORS = 'CORS'
    # 其它漏洞
    OTHER = "OTHER"