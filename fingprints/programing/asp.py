#!/usr/bin/env python 
# -*- coding:utf-8 -*-
from re import search, I, compile, error

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
    if suffix == ".asp" or suffix == ".aspx":
        return "ASP", None
    return None, None