#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/3/31 10:51 AM
# @Author  : w8ay
# @File    : enums.py

# We define some constants
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


class OS(object):
    LINUX = "Linux"
    WINDOWS = "Windows"
    DARWIN = "Darwin"


class PLACE:
    GET = "GET"
    POST = "POST"
    URI = "URI"
    COOKIE = "Cookie"
    USER_AGENT = "User-Agent"
    REFERER = "Referer"
    HOST = "Host"


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


class WEB_PLATFORM(object):
    PHP = "Php"
    ASP = "Asp"
    ASPX = "Aspx"
    JAVA = "Java"
    PYTHON = 'Python'


class WEB_SERVER(object):
    NGINX = "Nginx"
    APACHE = "Apache"
    TOMCAT = "Apache-Tomcat"
    IIS = "Iis"
    TENGINE = 'Tengine'

    
class Level(object):
    NONE = 0
    LOW = 1
    MIDDLE = 2
    HIGHT = 3


POST_HINT_CONTENT_TYPES = {
    POST_HINT.JSON: "application/json",
    POST_HINT.JSON_LIKE: "application/json",
    POST_HINT.MULTIPART: "multipart/form-data",
    POST_HINT.SOAP: "application/soap+xml",
    POST_HINT.XML: "application/xml",
    POST_HINT.ARRAY_LIKE: "application/x-www-form-urlencoded; charset=utf-8",
}


class VulType(object):
    # 命令注入漏洞，攻击者通过输入恶意命令试图在服务器上执行
    CMD_INNJECTION = "CMD_INNJECTION"
    # 代码注入漏洞，攻击者通过输入恶意代码试图在应用程序中执行
    CODE_INJECTION = "CODE_INJECTION"
    # 跨站脚本攻击（XSS），攻击者通过注入恶意脚本到网页中，当用户浏览该页时，恶意脚本会被执行
    XSS = "XSS"
    # SQL注入漏洞（SQLI），攻击者通过在应用程序的输入字段中插入或“注入”SQL命令，试图干扰正常的数据库查询执行
    SQLI = "SQLI"
    # 目录扫描漏洞，攻击者试图发现服务器上的目录和文件结构，通常是为了找到敏感信息或漏洞
    DIRSCAN = "DIRSCAN"
    # 路径遍历漏洞，攻击者试图访问服务器文件系统上的任意文件或目录，通常是通过修改URL中的路径参数
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    # XML外部实体注入（XXE），攻击者通过上传或引用恶意的XML文档，试图从服务器读取文件或执行其他恶意操作
    XXE = "XXE"
    # 暴力破解攻击，攻击者试图通过尝试大量的用户名和密码组合来破解账户
    BRUTE_FORCE = "BRUTE_FORCE"
    # JSONP漏洞，攻击者利用JSONP（JSON with Padding）技术绕过同源策略，执行跨站请求
    JSONP = "JSONP"
    # 服务器端请求伪造（SSRF），攻击者通过应用程序向服务器发送恶意的请求，试图访问内部系统或敏感服务
    SSRF = "SSRF"
    # 基线检查漏洞，通常指的是系统或应用程序未达到最低安全标准的问题
    BASELINE = "BASELINE"
    # 重定向漏洞，攻击者试图通过操纵应用程序的重定向功能，将用户重定向到恶意网站
    REDIRECT = "REDIRECT"
    # 回车换行注入（CRLF），攻击者试图通过注入回车（CR）和换行（LF）字符来操纵HTTP头部或数据
    CRLF = "CRLF"
    # 敏感信息泄露漏洞，应用程序不当地暴露敏感信息，如密码、密钥、用户数据等
    SENSITIVE = "SENSITIVE"
    # HTTP请求走私（Smuggling），攻击者通过操纵HTTP请求来绕过安全机制，实现未授权访问或其他恶意操作
    SMUGGLING = 'SMUGGLING'
    # 服务器端模板注入（SSTI），攻击者通过注入恶意模板代码到服务器端模板引擎中执行
    SSTI = 'SSTI'
    # 未授权访问（Unauth），攻击者试图访问他们没有权限访问的资源或服务
    UNAUTH = 'UNAUTH'
    # 接管漏洞
    TAKEOVER = 'TAKEOVER'
    # 文件上传
    FILEUPLOAD = 'FILEUPLOAD'