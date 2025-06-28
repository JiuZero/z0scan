#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error, findall


def fingerprint(suffix, headers, content):
    for item in headers.items():
        _ = findall(
            r'linux|ubuntu|gentoo|debian|dotdeb|centos|redhat|sarge|etch|lenny|squeeze|wheezy|jessie|red hat|scientific linux',
            str(item), I)
        if _:
            return "LINUX"
    return None