#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/25 10:08 PM
# @Author  : w8ay
# @File    : log.py
import logging
import sys
import colorlog

from thirdpart.ansistrm import ColorizingStreamHandler

LOGGER = logging.getLogger('z0scan')
LOGGER_HANDLER = ColorizingStreamHandler(sys.stdout)
LOGGER_HANDLER.level_map[logging.getLevelName("*")] = (None, "cyan", False)
LOGGER_HANDLER.level_map[logging.getLevelName("+")] = (None, "green", False)
LOGGER_HANDLER.level_map[logging.getLevelName("-")] = (None, "red", False)
LOGGER_HANDLER.level_map[logging.getLevelName("!")] = (None, "yellow", False)

FORMATTER = logging.Formatter("\r[\033[1;34m%(asctime)s\033[0m] [%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)

