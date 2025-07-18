#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error

keys = ['aliyunoss', 'amazons3', 'minio', 'ceph']

def fingerprint(suffix, headers, content):
    if 'server' in headers.keys():
        for _ in keys:
            if search(_, headers["server"], I):
                return "OSS"
    return None