#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/5

import threading, re, urllib
from urllib import parse as urlparse
from urllib.request import unquote

from lib.helper.simhash import Simhash
from lib.core.db import insertdb, select_all_db

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
    if query:
        params = urlparse.parse_qsl(query, True)
        for k, v in params:
            if v:
                params_new[k] = etl(v)
        query_new = urllib.parse.urlencode(params_new)

    path_new = etl(u.path, True)

    url_new = urlparse.urlunparse(
        (u.scheme, u.netloc, path_new, u.params, query_new, u.fragment))
    return url_new


def etl(str, STR=True, NUM=True, CHAR=True, OTHER=True, merge_num=False):
    '''
    传入一个字符串，将里面的字母转化为A，数字转化为N，特殊符号转换为T，其他符号或者字符转化成C
    :param str:
    :param onlyNUM:只换数字
    :return:
    '''
    chars = ""
    state = False
    for c in str:
        c = c.lower()
        if STR is True:
            if ord('a') <= ord(c) <= ord('z'):
                chars += 'A'
                state = True
        if NUM is True:
            if ord('0') <= ord(c) <= ord('9'):
                chars += 'N'
                state = True
        if CHAR is True:
            if c in Chars:
                chars += 'T'
                state = True
        if OTHER is True:
            if state == False:
                chars += 'C'
            else:
                chars += c
    if merge_num == True:
        chars = re.sub(r'N+', 'N', chars)
    return chars


def url_compare(url, link):
    dis = Simhash(url).distance(Simhash(link))
    if -2 < dis < 5:
        return True
    else:
        return False


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
    基于Google Simhash算法
    """

    def __init__(self):
        self.lock = threading.Lock()

    def _load_spider_data(self, plugin, netloc):
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