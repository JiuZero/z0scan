#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# 总配置

THREAD_NUM = 31  # 默认线程数量
SHOW_STATE = False # 显示扫描状态 (关闭它是为了避免影响插件的结果显示)
EXCLUDES = ["google", '.gov.', 'baidu', 'firefox']  # 扫描排除网址
RETRY = 2  # 超时重试次数
TIMEOUT = 10  # 超时时间
LEVEL = [0,1,2,3] # 0: 被动分析插件, 1: SQL注入等常见漏洞, 2: 目录枚举, 3: 中间件漏洞, 4: 命令执行等非常见漏洞
DEBUG = False # DEBUG模式
HEURiITIC_WAF_CHECK = True # 启发式Waf检测模式 (这个设置的关闭将不影响WAF的被动检测)
SKIP_SIMILAR_URL = True # 是否跳过相似URL下的扫描以减少请求


# 下游代理配置

PROXY_CONFIG_BOOL = False
PROXY_CONFIG = {
    # "http": "127.0.0.1:8080",
    # "https": "127.0.0.1:8080"
}


# 插件配置

ABLE = []  # 允许使用的插件
DISABLE = []  # 不允许使用的插件
XSS_LIMIT_CONTENT_TYPE = True  # 限制xss的content-type，为True时限制content-type为html，为False不限制
SQLi_TIME = 4 # SQLi插件延时时间 (不建议设置为大于4的数值)
PSEUDO_STATIC_KEYWORDS = ['id', 'pid', 'zid', 'user', 'page', 'category', 'column_id', 'tty'] # 伪静态SQL关键点参数（忽略大小写）


# 反连配置

USE_REVERSE = False  # 使用反连平台将False改为True
REVERSE_HTTP_IP = "127.0.0.1"  # 回连http IP地址，需要改为服务器ip，不能改为0.0.0.0，因为程序无法识别
REVERSE_HTTP_PORT = 9999  # 回连http端口
REVERSE_DNS = ""
REVERSE_RMI_IP = "127.0.0.1"  # Java RMI 回连IP,需要改为服务器ip，不能改为0.0.0.0，因为程序无法识别
REVERSE_RMI_PORT = 10002  # Java RMI 回连端口
REVERSE_SLEEP = 5  # 反连后延时检测时间，单位是(秒)
