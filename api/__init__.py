#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/23
# JiuZero 2025/3/2

import copy
import requests
from lib.core.option import init
from lib.core.plugins import PluginBase, _PluginBase
from lib.core.enums import PLACE, HTTPMETHOD, VulType, Type, POST_HINT
from lib.core.data import conf, KB, path
from lib.core.log import logger
from lib.core.threads import Threads
from lib.core.common import generateResponse, random_str, random_num, md5, splitUrlPath, url_dict2str, isjson
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.controller.controller import task_push_from_name, task_push, start
from lib.core.aichat import chat
from z0 import modulePath


__all__ = [
    'PluginBase', '_PluginBase', 'conf', 'KB', 'md5', 'splitUrlPath', 'url_dict2str', 'isjson', 
    'path', 'logger', 'PLACE', 'HTTPMETHOD', 'VulType', 'generateResponse', 'task_push_from_name', 'task_push', 'random_str', 'start', 'Type',
    'random_num', 'POST_HINT', 'Threads', 'chat'
]


def scan(url, module_name, conf={}, headers={}):
    root = modulePath()
    cmdline = {
        "level": 3
    }
    cmdline.update(conf)
    init(root, cmdline)
    r = requests.get(url, headers=headers)
    req = FakeReq(url, headers, HTTPMETHOD.GET)
    resp = FakeResp(r.status_code, r.content, r.headers)
    poc_module = copy.deepcopy(KB["registered"][module_name])
    poc_module.execute(req, resp)