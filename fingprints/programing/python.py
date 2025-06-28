#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error

def fingerprint(suffix, headers, content):
    _ = False
    for item in headers.items():
        _ = search(r'python|zope|zserver|wsgi|plone|_ZopeId', item[1], I) is not None
    # _ |= re.search(r'\.py$', content) is not None
    if _:
        return "PYTHON"
    return None