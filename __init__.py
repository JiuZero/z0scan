#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : __init__.py
import sys
import os
import inspect

# sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
def modulePath():
    """
    Get the program's directory, works in:
    - Normal Python execution
    - PyInstaller/Py2exe frozen bundles
    - Nuitka onefile/standalone builds
    - Edge cases where __file__ might not be available
    """
    if getattr(sys, 'frozen', False):
        # For PyInstaller, py2exe etc.
        return os.path.dirname(os.path.abspath(sys.executable))
    
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller onefile mode
        return os.path.abspath(sys._MEIPASS)
    
    if '__compiled__' in globals():
        # Nuitka compilation
        if getattr(sys, 'frozen', False) and hasattr(sys, '_nuitka_onefile_temp_dir'):
            # Nuitka onefile mode
            return os.path.dirname(os.path.abspath(sys.executable))
        else:
            # Nuitka standalone mode
            return os.path.dirname(os.path.abspath(sys.argv[0]))
    
    try:
        # Normal Python execution
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        try:
            # Fallback for interactive environments
            return os.path.dirname(os.path.abspath(sys.argv[0]))
        except:
            # Ultimate fallback
            return os.path.dirname(os.path.abspath(inspect.getsourcefile(modulePath)))