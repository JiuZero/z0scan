#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/3/31
# JiuZero 2025/2/23

"""
它的存在是出于规范化
并不必要
"""

# 数据库类型
class DBMS:
    DB2 = 'IBM DB2 database'
    MSSQL = 'Microsoft SQL database'
    ORACLE = 'Oracle database'
    SYBASE = 'Sybase database'
    POSTGRE = 'PostgreSQL database'
    MYSQL = 'MySQL database'
    JAVA = 'Java connector'
    ACCESS = 'Microsoft Access database'
    INFORMIX = 'Informix database'
    INTERBASE = 'Interbase database'
    DMLDATABASE = 'DML Language database'
    SQLITE = 'SQLite database'
    UNKNOWN = 'Unknown database'

# OS 指纹
class OS(object):
    LINUX = "LINUX"
    WINDOWS = "WINDOWS"
    DARWIN = "DARWIN"

# 设定注入的数据所修改的位置
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


class POST_HINT(object):
    NORMAL = "NORMAL"
    SOAP = "SOAP"
    JSON = "JSON"
    JSON_LIKE = "JSON-like"
    MULTIPART = "MULTIPART"
    XML = "XML (generic)"
    ARRAY_LIKE = "Array-like"

# 语言指纹
class WEB_PLATFORM(object):
    PHP = "PHP"
    ASP = "ASP"
    ASPX = "ASPX"
    JAVA = "JAVA"
    PYTHON = "PYTHON"

# 服务指纹
class WEB_SERVER(object):
    NGINX = "NGINX"
    APACHE = "APACHE"
    TOMCAT = "APACHE-TOMCAT"
    IIS = "IIS"
    TENGINE = "TENGINE"
    OSS = "OSS"

class Type(object):
    ANALYZE = "ANALYZE"#被动分析发现
    REQUEST = "REQUEST"#主动请求发现

class VulType(object):
    # 命令注入漏洞
    CMD_INNJECTION = "CMD_INNJECTION"
    # 代码注入漏洞
    CODE_INJECTION = "CODE_INJECTION"
    # 跨站脚本攻击（XSS）
    XSS = "XSS"
    # SQL注入漏洞（SQLI）
    SQLI = "SQLI"
    # 路径遍历漏洞
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    # XML外部实体注入（XXE）
    XXE = "XXE"
    # 服务器端请求伪造（SSRF）
    SSRF = "SSRF"
    # CSRF
    CSRF = "CSRF"
    # 重定向漏洞
    REDIRECT = "REDIRECT"
    # 回车换行注入（CRLF）
    CRLF = "CRLF"
    # 敏感信息泄露漏洞
    SENSITIVE = "SENSITIVE"
    # 服务器端模板注入（SSTI）
    SSTI = 'SSTI'
    # 未授权访问（Unauth）
    UNAUTH = 'UNAUTH'
    # 文件上传
    FILEUPLOAD = 'FILEUPLOAD'
    # CORS漏洞
    CORS = 'CORS'
    # 其它漏洞
    OTHER = "OTHER"