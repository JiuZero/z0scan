#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/22
 
from colorama import Fore, Style
import time, sys
from lib.core.data import conf, KB
import concurrent.futures
from functools import wraps

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

sys.stdout.reconfigure(line_buffering=False, write_through=True)

def non_blocking_delay(delay=0.01):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            future = _executor.submit(func, *args, **kwargs)
            time.sleep(delay)
            return future
        return wrapper
    return decorator

@non_blocking_delay(0.01)
def dataToStdout(data):
    print(data, flush=False)
    with open(KB.output.txt_filename, 'a', encoding='utf-8') as f:
        f.write(str(data) + '\n')


class colors:
    r = Fore.RED
    b = Fore.BLUE
    m = Fore.MAGENTA
    cy = Fore.CYAN
    g = Fore.GREEN
    y = Fore.YELLOW
    d = Style.DIM
    br = Style.BRIGHT
    e = Style.RESET_ALL
    
class logger:
    @staticmethod
    def _get_time():
        return time.strftime('%H:%M:%S', time.localtime(time.time()))
 
    @staticmethod
    def warning(value, origin=None, showtime=True):
        _time = f"[{colors.b}{logger._get_time()}{colors.e}] " if showtime else ""
        _origin = f"[{colors.cy}{origin}{colors.e}] " if origin else ""
        dataToStdout(
            f"{_time}[{colors.y}WAN{colors.e}] {_origin}{value}"
        )
 
    @staticmethod
    def error(value, origin=None, showtime=True):
        _time = f"[{colors.b}{logger._get_time()}{colors.e}] " if showtime else ""
        _origin = f"[{colors.cy}{origin}{colors.e}] " if origin else ""
        dataToStdout(
            f"{_time}[{colors.r}ERR{colors.e}] {_origin}{value}"
        )
 
    @staticmethod
    def info(value, origin=None, showtime=True):
        _time = f"[{colors.b}{logger._get_time()}{colors.e}] " if showtime else ""
        _origin = f"[{colors.cy}{origin}{colors.e}] " if origin else ""
        dataToStdout(
            f"{_time}[{colors.g}INF{colors.e}] {_origin}{value}"
        )
 
    @staticmethod
    def debug(value, origin=None, level=1):
        _origin = f"[{colors.cy}{origin}{colors.e}] " if origin else ""
        if conf.debug and conf.debug >= level:
            _time = logger._get_time()
            dataToStdout(
                f"[{colors.b}{_time}{colors.e}] [{colors.m}DBUG{colors.e}] {_origin}{value}"
            )
