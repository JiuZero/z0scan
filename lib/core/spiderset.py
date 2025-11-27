#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/5
# JiuZero/z0scan

import threading, re, urllib
from urllib import parse as urlparse
from urllib.parse import unquote

from lib.helper.simhash import Simhash
from lib.core.db import insertdb, select_all_db
from lib.core.data import conf

Chars = [',', '-', '_']

def url_etl(url):
    '''
    url泛化处理
    :param url: 原始url
    :return: 处理过后的url
    '''
    params_new = {}
    u = urlparse.urlparse(url)
    query = unquote(u.query)
    query_new = ''
    if conf.deduplicate_level == 1:
        config = {'STR': True, 'NUM': True, 'CHAR': True, 'OTHER': True, 'merge_num': False}
    else:
        config = {'STR': True, 'NUM': True, 'CHAR': True, 'OTHER': True, 'merge_num': True}
    if query:
        params = urlparse.parse_qsl(query, True)
        for k, v in params:
            if v:
                params_new[k] = etl(v, **config)
        query_new = urllib.parse.urlencode(params_new)

    path_new = etl(u.path, **config)

    url_new = urlparse.urlunparse(
        (u.scheme, u.netloc, path_new, u.params, query_new, u.fragment))
    return url_new


def etl(text, STR=True, NUM=True, CHAR=True, OTHER=True, merge_num=False):
    '''
    传入一个字符串，将里面的字母转化为A，数字转化为N，特殊符号转换为T，其他符号或者字符转化成C
    :param text: 输入字符串
    :param STR: 是否转换字母
    :param NUM: 是否转换数字  
    :param CHAR: 是否转换特殊字符
    :param OTHER: 是否转换其他字符
    :param merge_num: 是否合并连续数字
    :return: 归一化后的字符串
    '''
    chars = ""
    state = False
    for c in text:
        c = c.lower()
        char_processed = False
        
        if STR is True:
            if ord('a') <= ord(c) <= ord('z'):
                chars += 'A'
                char_processed = True
        if NUM is True and not char_processed:
            if ord('0') <= ord(c) <= ord('9'):
                chars += 'N'
                char_processed = True
        if CHAR is True and not char_processed:
            if c in Chars:
                chars += 'T'
                char_processed = True
        if OTHER is True and not char_processed:
            chars += 'C'
            char_processed = True
        elif not char_processed:
            chars += c
            
    if merge_num == True:
        chars = re.sub(r'N+', 'N', chars)
    return chars


def url_compare(etl1, etl2):
    """
    URL相似度比较
    :param etl1: 归一化后的URL1
    :param etl2: 归一化后的URL2  
    :return: 是否相似
    """
    dis = Simhash(etl1).distance(Simhash(etl2))
    if conf.deduplicate_level == 1:
        return -2 < dis < 5
    else:
        return -2 < dis < 8


def reduce_urls(ori_urls):
    '''
    对url列表去重
    :param ori_urls: 原始url列表
    :return: 去重后的url列表
    '''
    etl_urls = []
    result_urls = []
    for ori_url in ori_urls:
        etl = url_etl(ori_url)
        score = 0
        if etl_urls:
            for etl_url in etl_urls:
                if not url_compare(etl, etl_url):
                    score += 1
            if score == len(etl_urls):
                result_urls.append(ori_url)
                etl_urls.append(etl)
        else:
            etl_urls.append(etl)
            result_urls.append(ori_url)
    return result_urls


class SpiderSet(object):
    """
    基于Google Simhash算法的URL去重集合
    """

    def __init__(self):
        self.lock = threading.Lock()

    def _load_spider_data(self, plugin, netloc):
        """从数据库加载数据"""
        result = select_all_db('spiderset', 'etl_url', 
                              where='plugin = ? AND netloc = ?', 
                              where_values=[plugin, netloc])
        if result:
            return [row[0] for row in result]
        return []

    def add(self, url, plugin):
        """
        添加成功返回True，添加失败有重复返回False
        :param url:
        :param plugin:
        :return:bool
        """
        if conf.deduplicate_level == 0:
            return True
        ret = True
        if not (isinstance(url, str) and isinstance(plugin, str)):
            url = str(url)
            plugin = str(plugin)
        self.lock.acquire()
        try:
            if plugin == "PerHost":
                netloc = etl = url
            else:
                netloc = urlparse.urlparse(url).netloc
                etl = url_etl(url)  # url泛化表达式
            # 从数据库加载现有数据
            existing_urls = self._load_spider_data(plugin, netloc)
            score = 0
            for etl_url in existing_urls:
                if not url_compare(etl, etl_url):
                    score += 1
            if score == len(existing_urls):
                # 插入新记录
                insertdb('spiderset', {
                    'plugin': plugin,
                    'netloc': netloc,
                    'etl_url': etl
                })
            else:
                ret = False
        finally:
            self.lock.release()
        return ret
        
    def inside(self, url, plugin):
        if conf.deduplicate_level == 0:
            return True
        ret = False
        if not (isinstance(url, str) and isinstance(plugin, str)):
            url = str(url)
            plugin = str(plugin)
        self.lock.acquire()
        try:
            if plugin == "PerHost":
                netloc = etl = url
            else:
                netloc = urlparse.urlparse(url).netloc
                etl = url_etl(url)  # url泛化表达式
            # 从数据库加载现有数据
            existing_urls = self._load_spider_data(plugin, netloc)
            if not existing_urls:
                ret = True
            else:
                score = 0
                for etl_url in existing_urls:
                    if not url_compare(etl, etl_url):
                        score += 1
                if score == len(existing_urls):
                    ret = True
                else:
                    ret = False
        finally:
            self.lock.release()
        return ret