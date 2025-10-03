#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/3
import os
import re
from urllib.parse import urlparse, unquote

from lib.core.common import paramToDict
from lib.core.enums import PLACE, POST_HINT, HTTPMETHOD
from lib.core.settings import DEFAULT_GET_POST_DELIMITER, JSON_RECOGNITION_REGEX, XML_RECOGNITION_REGEX, \
    JSON_LIKE_RECOGNITION_REGEX, ARRAY_LIKE_RECOGNITION_REGEX, MULTIPART_RECOGNITION_REGEX


class FakeReq(object):

    def __init__(self, url, headers: dict, method=HTTPMETHOD.GET, data=""):

        self._https = False
        self._headers = headers
        self._method = method
        self._uri = ""
        self._body = data
        self._netloc = ""
        self._params = {}
        self._cookies = {}
        self._post_hint = None
        self._post_data = {}
        self._request_version = 1.1
        self._urlparse = urlparse(url)
        self._hostname = ""
        self._port = 80
        self._url = url
        self._scheme = "http"

        self._build()

    def _analysis_post(self):
        post_data = unquote(self._body)
        if re.search('([^=]+)=([^%s]+%s?)' % (DEFAULT_GET_POST_DELIMITER, DEFAULT_GET_POST_DELIMITER), post_data):
            self._post_hint = POST_HINT.NORMAL
            self._post_data = paramToDict(post_data, place=PLACE.NORMAL_DATA, hint=self._post_hint)

        elif re.search(JSON_RECOGNITION_REGEX, post_data):
            self._post_hint = POST_HINT.JSON

        elif re.search(XML_RECOGNITION_REGEX, post_data):
            self._post_hint = POST_HINT.XML

        elif re.search(JSON_LIKE_RECOGNITION_REGEX, post_data):
            self._post_hint = POST_HINT.JSON_LIKE

        elif re.search(ARRAY_LIKE_RECOGNITION_REGEX, post_data):
            self._post_hint = POST_HINT.ARRAY_LIKE
            self._post_data = paramToDict(post_data, place=PLACE.NORMAL_DATA, hint=self.post_hint)

        elif re.search(MULTIPART_RECOGNITION_REGEX, post_data):
            self._post_hint = POST_HINT.MULTIPART

    def _build(self):
        p = self._urlparse
        self._scheme = p.scheme
        port = 80
        if p.scheme == "https":
            port = 443
            self._https = True
        hostname = p.netloc
        if ":" in p.netloc:
            try:
                hostname, port = p.netloc.split(":")
                port = int(port)
            except:
                hostname = p.netloc
                port = 80
        self._hostname = hostname
        self._port = port

        if self._method == HTTPMETHOD.POST:
            # 分析post数据类型
            self._analysis_post()
        self._uri = p.path
        if p.query:
            self._uri = p.path + "?" + p.query
            self._params = paramToDict(p.query, place=PLACE.PARAM)

        self._netloc = "{}://{}".format(p.scheme, p.netloc)
        self._path = p.path
        if "cookie" in self._headers or "Cookie" in self._headers:
            _cookies = self._headers.get("cookie", self._headers.get("Cookie", {}))
            if _cookies:
                self._cookies = paramToDict(_cookies, place=PLACE.COOKIE)

    # 原始请求体
    @property
    def raw(self):
        # Build request
        req_data = '%s %s %s\r\n' % (self.method, self._uri, self._request_version)
        # Add headers to the request
        for k, v in self._headers.items():
            req_data += k + ': ' + v + '\r\n'
        req_data += '\r\n'
        req_data += self._body
        return req_data

    # 请求方法
    @property
    def method(self) -> str:
        return self._method

    # 后缀名
    @property
    def suffix(self) -> str:
        exi = os.path.splitext(self._urlparse.path)[1]
        return exi

    # 头部参数
    @property
    def headers(self) -> dict:
        return self._headers

    # 域名/主机地址
    @property
    def hostname(self) -> str:
        return self._hostname

    # 端口
    @property
    def port(self) -> int:
        return self._port

    # cookies参数
    @property
    def cookies(self) -> dict:
        return self._cookies

    # GET请求参数(不含伪静态)
    @property
    def params(self) -> dict:
        return self._params
    @params.setter
    def params(self, value):
        self._params = value
    
    # 请求协议
    @property
    def protocol(self) -> str:
        return self._scheme

    # POST请求类型
    @property
    def post_hint(self) -> str:
        return self._post_hint

    # data请求参数
    @property
    def data(self) -> dict:
        return self._post_data
    @data.setter
    def data(self, postdata):
        self._post_data = postdata

    # 路径
    @property
    def path(self) -> str:
        return self._path

    # 完整URL
    @property
    def url(self) -> str:
        return self._url

    # 请求Body
    @property
    def body(self) -> str:
        return self._body
    
    @property
    def netloc(self) -> str:
        p = self._urlparse
        netloc = "{}://{}{}".format(p.scheme, p.netloc, p.path)
        return netloc
