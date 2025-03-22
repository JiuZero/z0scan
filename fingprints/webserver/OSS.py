#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    OSS

from re import search, I, compile, error
from lib.core.enums import WEB_SERVER
from api import KB

def _prepare_pattern(pattern):
    """
    Strip out key:value pairs from the pattern and compile the regular
    expression.
    """
    regex, _, rest = pattern.partition('\;')
    try:
        return compile(regex, I)
    except error as e:
        return compile(r'(?!x)x')

keys = ['aliyunoss', 'amazons3', 'minio', 'ceph']

def fingerprint(headers, content):
    if 'server' in headers.keys():
        for _ in keys:
            if search(_, headers["server"], I): return WEB_SERVER.OSS, None
    return None, None