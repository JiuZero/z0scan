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
class POST_HINT:
    NORMAL = "NORMAL"
    JSON = "JSON"
    XML = "XML"
    JSON_LIKE = "JSON_LIKE"
    MULTIPART = "MULTIPART"
    ARRAY_LIKE = "ARRAY_LIKE"
    SOAP = "SOAP"

class PLACE:
    # 常规情况
    PARAM = "PARAM"
    NORMAL_DATA = "NORMAL_DATA"
    XML_DATA = "XML_DATA"
    MULTIPART_DATA = "MULTIPART_DATA"
    COOKIE = "COOKIE"
    URL = "URL"
    ARRAY_LIKE_DATA = "ARRAY_LIKE_DATA"
    SOAP_DATA = "SOAP_DATA"
    # JSON 情况
    JSON_DATA = "JSON"
    FORM_VALUE_JSON = "FORM_VALUE_JSON"
    ## 值中的二级参数
    PARAM_VALUE_JSON = "PARAM_VALUE_JSON"
    COOKIE_JSON_VALUE = "COOKIE_JSON_VALUE"
    
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