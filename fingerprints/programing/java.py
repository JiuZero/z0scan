#!/usr/bin/env python 
# -*- coding:utf-8 -*-

from re import search, I, compile, error

def fingerprint(suffix, headers, content):
    if suffix == ".jsp" or suffix == ".do" or suffix == ".action":
        return "JAVA"
    _ = False
    for item in headers.items():
        _ = search(r'java|servlet|jsp|jboss|glassfish|oracle|jre|jdk|jsessionid', str(item)) is not None
        if not _:
            _ |= search(r'\.jsp$|\.jspx$|.do$|\.wss$|\.action$', content) is not None
        if _:
            return "JAVA"
    return None
