#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : __init__.py
import sys
import os
import inspect

# sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
def modulePath():
    try:
        if "__compiled__" in globals():
            _ = sys.argv[0]
        elif hasattr(sys, "frozen"):
            _ = sys.executable
        else:
            _ = __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)
    abs_path = os.path.realpath(_)
    dir_path = os.path.dirname(abs_path)
    return dir_path