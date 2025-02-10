#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    IIS

from re import search, I, compile, error, IGNORECASE
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
        _ = search(r"(?:microsoft-)?iis/([\d\.]+)", headers["server"], I)
    if _:
        _ = _.group(1) if _ else ""
        KB["SERVER_VERSION"][WEB_SERVER.IIS] = _
        return WEB_SERVER.IIS
    else:
        KB["SERVER_VERSION"][WEB_SERVER.IIS] = None