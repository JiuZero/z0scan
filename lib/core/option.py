#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/6/17

import os, sys
import threading
import time
from queue import Queue
from config import config
from colorama import init as cinit
from lib.core.common import random_UA, ltrim
from lib.core.data import path, KB, conf
from lib.core.log import dataToStdout, logger, colors
from lib.core.exection import PluginCheckError
from lib.core.loader import load_file_to_module
from lib.core.db import initdb
from lib.core.output import OutPut
from lib.core.settings import banner, DEFAULT_USER_AGENT
from lib.core.spiderset import SpiderSet
from thirdpart.console import getTerminalSize
from lib.patch.requests_patch import patch_all
from lib.patch.ipv6_patch import ipv6_patch
from prettytable import PrettyTable

def setPaths(root):
    path.root = root
    path.certs = os.path.join(root, 'certs')
    path.config = os.path.join(root, 'config')
    path.lists = os.path.join("config", "lists")
    path.others = os.path.join("config", "others")
    path.scanners = os.path.join(root, 'scanners')
    path.fingprints = os.path.join(root, "fingprints")
    path.output = os.path.join(root, "output")


def initKb():
    KB['continue'] = False  # 线程一直继续
    KB['registered'] = dict()  # 注册的漏洞插件列表
    KB['fingerprint'] = dict()  # 注册的指纹插件列表
    KB['task_queue'] = Queue()  # 初始化队列
    KB["spiderset"] = SpiderSet()  # 去重复爬虫
    KB['start_time'] = time.time()  # 开始时间
    KB["lock"] = threading.Lock()  # 线程锁
    if not conf.list:
        KB["output"] = OutPut()
    KB["running_plugins"] = dict()
    KB['finished'] = 0  # 完成数量
    KB["result"] = 0  # 结果数量
    KB["running"] = 0  # 正在运行数量

    KB.limit = False

def _list():
    """列出所有已注册的插件信息"""
    if "registered" not in KB or not KB["registered"]:
        logger.warning("No plugins loaded.")
        return
    table = PrettyTable()
    table.field_names = ["Name", "Description", "Version", "Risk Level"]
    table.align["Name"] = "l"
    table.align["Description"] = "l"
    for plugin_name, plugin_instance in KB["registered"].items():
        if plugin_name == "loader":
            continue
        name = getattr(plugin_instance, "name", "N/A")
        desc = getattr(plugin_instance, "desc", "N/A")
        version = getattr(plugin_instance, "version", "N/A")
        risk = getattr(plugin_instance, "risk", "N/A")
        table.add_row([
            name if name != "N/A" else "N/A",
            desc,
            version,
            risk,
        ])
    print(f"\n{colors.y}Loaded Plugins:{colors.e}")
    print(table)
    print(f"Total plugins: {colors.y}{len(KB['registered']) - 1}{colors.e}\n")
    """列出所有模糊测试字典"""
    if not hasattr(conf, "lists") or not conf.lists:
        logger.warning("No fuzz dictionaries loaded.")
        return
    table = PrettyTable()
    table.field_names = ["Dictionary Name", "Entry Count"]
    table.align["Dictionary Name"] = "l"
    for name, entries in conf.lists.items():
        table.add_row([name, len(entries)])
    print(f"\n{colors.y}Loaded Fuzz Dictionaries:{colors.e}")
    print(table)
    print(f"Total dictionaries: {colors.y}{len(conf.lists)}{colors.e}\n")

def initPlugins():
    # 加载检测插件
    for root, dirs, files in os.walk(path.scanners):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            q = os.path.splitext(_)[0]
            if conf.able and q not in conf.able and q != 'loader':
                continue
            if conf.disable and q in conf.disable:
                continue
            filename = os.path.join(root, _)
            mod = load_file_to_module(filename)
            try:
                mod = mod.Z0SCAN()
                mod.checkImplemennted()
                plugin = os.path.splitext(_)[0]
                plugin_type = os.path.split(root)[1]
                relative_path = ltrim(filename, path.root)
                if getattr(mod, 'type', None) is None:
                    setattr(mod, 'type', plugin_type)
                if getattr(mod, 'path', None) is None:
                    setattr(mod, 'path', relative_path)
                KB["registered"][plugin] = mod
            except PluginCheckError as e:
                logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
            except AttributeError as e:
                logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                raise
    if not conf.list:
        logger.info(f'Load Scanner  : {colors.y}{len(KB["registered"])-1}{colors.e}')
    
    # 加载指纹识别插件
    num = 0
    for root, dirs, files in os.walk(path.fingprints):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            filename = os.path.join(root, _)
            if not os.path.exists(filename):
                continue
            name = os.path.split(os.path.dirname(filename))[-1]
            mod = load_file_to_module(filename)
            if not getattr(mod, 'fingerprint'):
                logger.error("filename: {} load faild,not function 'fingerprint'".format(filename))
                continue
            if name not in KB["fingerprint"]:
                KB["fingerprint"][name] = []
            KB["fingerprint"][name].append(mod)
            num += 1
    if not conf.list:
        logger.info(f'Load Finger   : {colors.y}{num}{colors.e}')
    
    # 加载模糊字典并储存为列表
    conf.lists = dict()
    for root, dirs, files in os.walk(path.lists):
        files = list(filter(lambda x: x.endswith('.txt'), files))
        for _ in files:
            name = os.path.splitext(_)[0]
            file = os.path.join(path.lists, _)
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = [line.strip() for line in f.readlines() if line.strip()]
                    # TODO: replace
                    conf.lists[name] = content
            except Exception as e:
                logger.warning(f'Error loading list {file}: {str(e)}')


def _merge_options(cmdline):
    # 命令行配置 将覆盖 config配置
    if hasattr(cmdline, "items"):
        cmdline_items = cmdline.items()
    else:
        cmdline_items = cmdline.__dict__.items()
    for key, value in vars(config).items():
        conf[key.lower()] = value
        continue
    for key, value in cmdline_items:
        conf[key] = value
        continue


def _set_conf():
    # show version
    if conf.version:
        sys.exit(0)

    if conf.list:
        initKb()
        initPlugins()
        _list()
        sys.exit(0)

    # server_addr
    if isinstance(conf["server_addr"], str):
        if ":" in conf["server_addr"]:
            splits = conf["server_addr"].split(":", 2)
            conf["server_addr"] = tuple([splits[0], int(splits[1])])
        else:
            conf["server_addr"] = tuple([conf["server_addr"], conf.default_proxy_port])

    # threads
    conf["threads"] = int(conf["threads"])

    # proxy
    if isinstance(conf["proxy"], str) and "@" in conf["proxy"]:
        conf["proxy_config_bool"] = True
        method, ip = conf["proxy"].split("@")
        conf["proxy"] = {
            method.lower(): ip
        }

    # user-agent
    if conf.random_agent:
        conf.agent = random_UA()
    else:
        conf.agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101'


def _init_stdout():
    logger.info(f"Threads       : {colors.y}{conf.threads} / {conf.plugin_threads}{colors.e}")
    logger.info(f"Level         : {colors.y}[#{conf.level}]{colors.e}")
    logger.info(f"Risk          : {colors.y}{conf.risk}{colors.e}")
    if conf.ignore_waf:
        logger.info('IGNORE WAF    : True')
    if conf.ignore_fingerprint:
        logger.info('IGNORE FINGERS: True')
    # 不扫描网址
    if len(conf["excludes"]):
        logger.info("SKIP SCAN     : {}".format(repr(conf["excludes"])))
    # 指定扫描插件
    if conf.disable:
        logger.info("DIS PLUGINS   : {}".format(repr(conf.disable)))
    if conf.able:
        logger.info("ABLE PLUGINS  : {}".format(repr(conf.able)))
    if conf.html:
        logger.info("HTML PATH     : {}".format(KB.output.get_html_filename()))
    logger.info("JSON PATH     : {}".format(KB.output.get_filename()))

def init(root, cmdline):
    cinit(autoreset=True)
    setPaths(root)
    dataToStdout(banner)
    _merge_options(cmdline)
    _set_conf()
    initKb()
    initPlugins()
    initdb(root)
    _init_stdout()
    patch_all()
    ipv6_patch()