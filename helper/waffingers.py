#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
# 出于指纹数量的需要而使用以下形式：
WAF名|匹配位置|正则匹配

例：
360|server|xxxxx（尝试在头部中寻找键为server的头部，忽略大小写）
360|text|'https://www.baidu.com'（在响应内容中匹配）
"""

fingers = (
    r'360|x-powered-by-360wzb|wangzhan\.360\.cn', 
    '360|x-powered-by|360',
    '360wzws|server|360wzws', 
    r'360 AN YU|text|Sorry! your access has been intercepted by AnYu',
    '360 AN YU|text|AnYu- the green channel', 
    'BaiduYunjiasu|server|yunjiasu-nginx',
    'CloudFlare CDN|server|cloudflare-nginx', 
    'CloudFlare CDN|server|cloudflare',
    r'Cloudflare CDN|cf-ray|.+', 
    'Cloudfront CDN|server|cloudfront',
    'Cloudfront CDN|x-cache|cloudfront', 
    r'Cloudfront CDN|x-cache|Error\sfrom\scloudfront',
    'mod_security|server|mod_security', 
    'mod_security|server|Mod_Security',
    'Airee CDN|server|Airee', 
    'ModSecurity|server|NYOB',
    'ModSecurity|server|NOYB', 
    'ModSecurity|server|.*mod_security',
    'Safe3|x-powered-by|Safe3WAF', 
    'Safe3|server|Safe3 Web Firewall',
    r'Safedog|x-powered-by|WAF/2\.0', 
    'Safedog|server|Safedog', 
    'Safedog|set-cookie|Safedog',
    'Safedog|text|404.safedog.cn/images/safedogsite/broswer_logo.jpg', 
    'WatchGuard|server|WatchGuard',
    'Yundun|server|YUNDUN', 
    'Yundun|x-cache|YUNDUN', 
    'Yunsuo|set-cookie|yunsuo', 
    'Immunify360|server|imunify360',
    'ChinaCache CDN|server|ChinaCache',
    'HuaweiCloudWAF|server|HuaweiCloudWAF', 
    'HuaweiCloudWAF|set-cookie|HWWAFSESID',
    'aliyun|text|errors.aliyun.com', 
    'aliyun|text|cdn.aliyuncs.com',
    'aliyun|set-cookie|aliyungf_tc=',
    'D盾|text|D盾_拦截提示', 
    '华为防火墙|server|Eudemon.+',
)
