#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/5
# JiuZero 2025/4/11

from lib.core.log import logger
from threading import Lock

rlog = logger()

reverse_records = []
reverse_lock = Lock()