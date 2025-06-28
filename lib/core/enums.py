#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/7

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
    JSON_LIKE = "JSON_LIKE"
    MULTIPART = "MULTIPART"
    XML = "XML"
    ARRAY_LIKE = "ARRAY_LIKE"

# 设定注入的数据所处位置
class PLACE:
    PARAM = "PARAM"
    URL = "URL"
    COOKIE = "COOKIE"
    # 避免出现含XML等格式的请求包中GET参数与cookie参数中存在漏洞
    # 而插件仅通过post_hint过滤后遗漏漏洞点
    # DATA = "DATA"
    NORMAL_DATA = "NORMAL_DATA"
    JSON_DATA = "JSON_DATA"
    XML_DATA = "XML_DATA"
    MULTIPART_DATA = "MULTIPART_DATA"
    ARRAY_LIKE_DATA = "ARRAY_LIKE_DATA"
    SOAP_DATA = "SOAP_DATA"

# 插件扫描方式
class Type(object):
    ANALYZE = "ANALYZE" # 被动分析发现
    REQUEST = "REQUEST" # 主动请求发现

class VulType(object):
    CMD_INNJECTION = "CMD_INNJECTION" # 命令注入漏洞
    CODE_INJECTION = "CODE_INJECTION" # 代码注入漏洞
    XSS = "XSS" # 跨站脚本攻击
    SQLI = "SQLI" # SQL注入漏洞
    PATH_TRAVERSAL = "PATH_TRAVERSAL" # 路径遍历漏洞
    XXE = "XXE" # XML外部实体注入
    SSRF = "SSRF" # 服务器端请求伪造
    CSRF = "CSRF" # CSRF
    REDIRECT = "REDIRECT" # 重定向漏洞
    WEAK_PASSWORD = "WEAK_PASSWORD" # 弱口令
    CRLF = "CRLF" # 换行注入
    SENSITIVE = "SENSITIVE" # 敏感信息泄露漏洞
    SSTI = 'SSTI' # 服务器端模板注入
    UNAUTH = 'UNAUTH' # 未授权访问
    FILEUPLOAD = 'FILEUPLOAD' # 文件上传
    CORS = 'CORS' # CORS漏洞
    OTHER = "OTHER" # 其它漏洞