#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/2/21
 
from colorama import Fore, Style
import time, sys, os
 
def dataToStdout(data, bold=False):
    """
    Writes text to the stdout (console) stream
    """
    data += '\n'
    os.write(sys.stdout.fileno(), data.encode())
    '''
    sys.stdout.write(data)
 
    try:
        sys.stdout.flush()
    except IOError:
        pass
    '''
    return
 
class LOGGER:
    r = Fore.RED
    b = Fore.BLUE
    m = Fore.MAGENTA
    cy = Fore.CYAN
    g = Fore.GREEN
    y = Fore.YELLOW
    e = Style.RESET_ALL
 
    @staticmethod
    def _get_time():
        return time.strftime('%H:%M:%S', time.localtime(time.time()))
 
    @staticmethod
    def warning(value):
        _time = LOGGER._get_time()
        dataToStdout(
            "[{}{}{}] [{}WARN{}] {}".format(LOGGER.b, _time, LOGGER.e, LOGGER.y, LOGGER.e, value)
        )
 
    @staticmethod
    def error(value, origin=None):
        _time = LOGGER._get_time()
        if origin:
            dataToStdout(
                "[{}{}{}] [{}ERROR{}] [{}{}{}] {}".format(LOGGER.b, _time, LOGGER.e, LOGGER.r, LOGGER.e, LOGGER.cy, origin, LOGGER.e, value)
            )
        else:
            dataToStdout(
                "[{}{}{}] [{}ERROR{}] {}".format(LOGGER.b, _time, LOGGER.e, LOGGER.r, LOGGER.e, value)
            )
 
    @staticmethod
    def info(value):
        _time = LOGGER._get_time()
        dataToStdout(
            "[{}{}{}] [{}INFO{}] {}".format(LOGGER.b, _time, LOGGER.e, LOGGER.g, LOGGER.e, value)
        )
 
    @staticmethod
    def debug(value, verify=True, origin=None):
        if verify:
            _time = LOGGER._get_time()
            if origin:
                dataToStdout(
                    "[{}{}{}] [{}DEBUG{}] [{}{}{}] {}".format(LOGGER.b, _time, LOGGER.e, LOGGER.m, LOGGER.e, LOGGER.cy, origin, LOGGER.e, value)
                )
            else:
                dataToStdout(
                    "[{}{}{}] [{}DEBUG{}] {}".format(LOGGER.b, _time, LOGGER.e, LOGGER.m, LOGGER.e, value)
                )
