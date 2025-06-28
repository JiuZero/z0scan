#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error

keys = [ r"Win32|Win64", r"WinCE" ]

def fingerprint(suffix, headers, content):
    if suffix == ".asp" or suffix == ".aspx":
        return "WINDOWS"
    if 'server' in headers.keys():
        for _ in keys:
            if search(_, headers["server"], I):
                return "WINDOWS"
    return None