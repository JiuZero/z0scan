#!/usr/bin/env python 
# -*- coding:utf-8 -*-
from re import search, I, compile, error

def fingerprint(suffix, headers, content):
    if suffix == ".asp" or suffix == ".aspx":
        return "ASP"
    _ = False
    for item in headers.items():
        _ = search(r'asp.net|x-aspnet-version|x-aspnetmvc-version', str(item), I) is not None
        if not _:
            _ |= search(r'(__VIEWSTATE\W*)', content) is not None
        if not _:
            _ |= search(r'\.asp$|\.aspx$', content) is not None
        if _:
            return "ASP"
    return None