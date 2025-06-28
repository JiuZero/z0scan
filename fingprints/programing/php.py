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
    if suffix == ".php" or suffix == ".phtml":
        return "PHP"
    if _prepare_pattern(r"\.php(?:$|\?)").search(content):
        return "PHP"
    _ = False
    for item in headers.items():
        _ = search(r'x-php-pid|php\S*|phpsessid', str(item)) is not None
    if _:
        return "PHP"
    return None