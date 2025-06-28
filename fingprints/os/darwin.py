#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error

def fingerprint(suffix, headers, content):
    _ = False
    for item in headers.items():
        _ = search(r'mac|darwin|macos\S*', str(item)) is not None
        if _:
            return "DARWIN"
    return None
