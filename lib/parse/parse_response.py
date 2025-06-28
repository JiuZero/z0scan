#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/3

import chardet

class FakeResp(object):

    def __init__(self, status_code: int, body: bytes, headers: dict):
        self._status_code = status_code
        self._body = body
        self._headers = headers
        self._decoding = chardet.detect(self._body)['encoding']  # 探测当前的编码

    @property
    def status_code(self):
        return self._status_code

    @property
    def content(self):
        return self._body

    @property
    def headers(self):
        # TODO: lower keys
        return self._headers

    @property
    def raw(self):
        response_raw = "HTTP/1.1 {} \r\n".format(self._status_code)
        for k, v in self._headers.items():
            response_raw += "{}: {}\r\n".format(k, v)
        response_raw += "\r\n"
        response_raw += self.text
        return response_raw

    @property
    def text(self):
        if self._decoding:
            try:
                return self._body.decode(self._decoding)
            except Exception as e:
                return self._body.decode('utf-8', "ignore")
        return self._body.decode('utf-8', "ignore")
