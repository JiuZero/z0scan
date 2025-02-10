#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    Ubuntu

from re import search, I, compile, error

from lib.core.enums import OS


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

keys_1 = [
    "Ubuntu", "Unix", "SUSE", "FreeBSD", "Scientific Linux", r"SunOS( [\d\.]+)?\;version:\1", "Red Hat", "CentOS", "Fedora", "Debian"
]
keys_2 = [
    "Ubuntu", r"SUSE(?:/?\s?-?([\d.]+))?\;version:\1", "Scientific Linux", "Red Hat", "CentOS", "gentoo", r"(?:Debian|dotdeb|(sarge|etch|lenny|squeeze|wheezy|jessie))\;version:\1"
]

def fingerprint(headers, content):
    _ = False
    if 'server' in headers.keys():
        for _ in keys_1:
            if search(_, headers["server"], I): return OS.LINUX
        
    if 'x-powered-by' in headers.keys():
        for _ in keys_2:
            if search(r"Ubuntu", headers["x-powered-by"], I): return OS.LINUX
    
    if 'servlet-engine' in headers.keys():
        if search(r"SunOS( [\d\.]+)?\;version:\1", headers["servlet-engine"], I): return OS.LINUX

