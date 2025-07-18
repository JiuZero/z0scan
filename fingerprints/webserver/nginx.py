#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error

def fingerprint(suffix, headers, content):
    _ = False
    if 'server' in headers.keys():
        _ |= search(r"nginx(?:/([\d.]+))?\;version:\1", headers["server"], I) is not None
    if _: return "NGINX"
    return None