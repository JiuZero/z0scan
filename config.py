#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
总配置
"""

THREADS = 18  # 默认线程数量
EXCLUDES = ["google", '.gov.', 'baidu', 'firefox', 'microsoft', '.bing.', 'msn.cn']  # 排除包含关键字的网址
DEFAULT_PROXY_PORT = 5920 # 被动模式默认监听端口
RETRY = 2  # 超时重试次数
TIMEOUT = 6  # 超时时间
LEVEL = 2 # 0:纯被动分析模式，不做额外请求，即不加载Payload | 1:最低请求量的扫描，最低的业务影响 | 2:中等请求量的扫描，Payload多为通用 | 3:大量请求扫描，Payload覆盖面更广
RISK = [0, 1, 2] # -1:几乎无危害的常见漏洞，0:可能导致危害产生，1:低危害，2. 中等危害，3:高危害
CRAWL_THREADS = 4 # 爬虫线程
IPV6 = False # 需网络支持ipv6（使用此参数优先ipv6地址，ipv6无记录再使用ipv4地址）
PSEUDO_STATIC_KEYWORDS = ['id', 'pid', 'cid', 'user', 'page', 'category', 'column_id', 'tty'] # 伪静态关键点参数（忽略大小写）
SMARTSCAN = {
    "enable": False, 
    "api_url": "https://free.v36.cm/v1/",
    "model": "gpt-3.5-turbo", 
    "api_key": "", 
} # AI智能插件优化（支持所有openai库所能调用的模型）
MAX_DIR = 2 # PerDir插件的扫描深度(目录深度)
CONSOLE_PORT = 9331 # console交互通信端口
HIDDEN_VUL_REMINDER = True # 漏洞隐患提醒
BLOCK_COUNT = 20 # 请求多次失败后诊断为网站对本机IP封禁，加入请求黑名单
STATUS_FLASH_TIME = 60 # 扫描状态输出间隔(>=60)
NOTICE = {
    # 企业微信推送
    "wechat": {
        "enable": False, 
        "corp_id": "", 
        "secret": "", 
        "agent_id": "", 
        "user_list": [''], 
    },
    # 钉钉推送
    "dingtalk": {
        "enable": False, 
        "token": "", 
    },
    # Server酱推送
    "ftqq": {
        "enable": False,
        "key": "",
    }
}


"""
插件配置
"""

PLUGIN_THREADS = 2 # 插件内线程（针对多参数情况）
DISLOAD = ["unauth", "redos"]  # 不加载的插件
# sqli-time
SQLi_TIME = 4 # SQLi插件延时时间
# xss
XSS_LIMIT_CONTENT_TYPE = True  # 限制xss的content-type，为True时限制content-type为html，为False不限制
# leakpwd-page
LOGINPAGE_SQLI = True # SQL后台万能账号密码爆破
USERNAME_KEYWORDS = ["user", "name", "zhanghao", "yonghu", "email", "account"] # 用户名参数关键字列表
PASSWORD_KEYWORDS = ["pass", "pw", "mima"] # 密码参数关键字列表
CAPTCHA_KEYWORDS = ["验证码", "captcha", "验 证 码", "点击更换", "点击刷新", "看不清", "认证码", "安全问题"] # 验证码关键字列表
LOGIN_KEYWORDS = ["用户名", "密码", "login", "denglu", "登录", "user", "pass", "yonghu", "mima", "admin"] # 检测登录页面关键字
BRUTE_DELAY = 0.03  # 每次请求之后sleep的间隔
# ssti
SSTI_LEVEL = 0  # 0-5 扫描速度，越往后数据包越多，个别fuzz情况可配置大一些


"""
服务端&客户端反连配置
"""

REVERSE = {
    # 客户端
    "sleep": 5,  # 反连后延时检测时间，单位是(秒)
    # 服务端&客户端
    "http_ip": "127.0.0.1",   # 反连HTTP IP地址
    "http_port": 9999,   # 反连HTTP端口
    "dns_enable": True, 
    "dns_domain": "log.evilhex.top",  # 配置NS的域名
    "dns_port": 53,  # DNS服务默认端口
    # 下面两种暂时没有应用场景
    "rmi_enable": False, 
    "rmi_ip": "127.0.0.1",   # Java RMI 反连IP
    "rmi_port": 10002,   # Java RMI 反连端口
    "ldap_enable": False,
    "ldap_ip": "127.0.0.1",  # LDAP 反连IP
    "ldap_port": 10003,  # LDAP 反连端口
}