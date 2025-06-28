#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/22
 
from colorama import Fore, Style
import time, os, sys, threading
from lib.core.data import conf


def dataToStdout(data, enter=True):
    os.write(sys.stdout.fileno(), b'\r')
    os.write(sys.stdout.fileno(), b'\x1b[2K')
    os.write(sys.stdout.fileno(), data.encode())
    return


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
    def warning(value):
        _time = logger._get_time()
        dataToStdout(
            f"[{colors.b}{_time}{colors.e}] [{colors.y}WAN{colors.e}] {value}\n"
        )
 
    @staticmethod
    def error(value, origin=None):
        _time = logger._get_time()
        if origin:
            dataToStdout(
                f"[{colors.b}{_time}{colors.e}] [{colors.r}ERR{colors.e}] [{colors.cy}{origin}{colors.e}] {value}\n"
            )
        else:
            dataToStdout(
                f"[{colors.b}{_time}{colors.e}] [{colors.r}ERR{colors.e}] {value}\n"
            )
 
    @staticmethod
    def info(value):
        _time = logger._get_time()
        dataToStdout(
            f"[{colors.b}{_time}{colors.e}] [{colors.g}INF{colors.e}] {value}\n"
        )
 
    @staticmethod
    def debug(value, origin=None, level=1):
        if conf.debug and conf.debug >= level:
            _time = logger._get_time()
            if origin:
                dataToStdout(
                    f"[{colors.b}{_time}{colors.e}] [{colors.m}DBUG{colors.e}] [{colors.cy}{origin}{colors.e}] {value}\n"
                )
            else:
                dataToStdout(
                    f"[{colors.b}{_time}{colors.e}] [{colors.m}DBUG{colors.e}] {value}\n"
                )
