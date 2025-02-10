#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    Nginx

from re import search, I, compile, error
from lib.core.enums import WEB_SERVER
from lib.core.data import KB

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

def fingerprint(headers, content):
    _ = False
    if 'server' in headers.keys():
        _ = search(r"nginx(?:/([\d.]+))?\;version:\1", headers["server"], I) is not None
    if _:
        _ = _.group(1) if _ else ""
        KB["SERVER_VERSION"][WEB_SERVER.NGINX] = _
        return WEB_SERVER.NGINX
    else:
        KB["SERVER_VERSION"][WEB_SERVER.NGINX] = None