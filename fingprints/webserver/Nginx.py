#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    Nginx

from re import search, I, compile, error
from api import KB

def _prepare_pattern(pattern):
    """
    Strip out key:value pairs from the pattern and compile the regular
    expression.
    """
    regex, _, rest = pattern.partition(r'\;')
    try:
        return compile(regex, I)
    except error as e:
        return compile(r'(?!x)x')

def fingerprint(suffix, headers, content):
    version = None
    _ = False
    if 'server' in headers.keys():
        _ = search(r"nginx(?:/([\d.]+))?\;version:\1", headers["server"], I)
    if _:
        _ = _.group(1) if _ else ""
        return "NGINX", version
    return None, None