#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/6/17

import os, sys, shutil
import threading, asyncio
import time
from queue import Queue
from config import config
from colorama import init as cinit
from lib.core.common import random_UA, ltrim, check_reverse
from lib.core.data import path, KB, conf
from lib.core.log import dataToStdout, logger, colors
from lib.core.exection import PluginCheckError
from lib.core.loader import load_file_to_module
from lib.core.db import initdb, execute_sqlite_command
from lib.core.output import OutPut
from lib.core.settings import banner, DEFAULT_USER_AGENT, VERSION
from lib.core.spiderset import SpiderSet
from thirdpart.console import getTerminalSize
from lib.patch.requests_patch import patch_all
from lib.patch.ipv6_patch import ipv6_patch
from prettytable import PrettyTable
from lib.core.console import Client, BackgroundServer
from lib.core.aichat import chat
from pathlib import Path
from lib.core.updater import AutoUpdater

def setPaths(root):
    path.root = root
    path.certs = os.path.join(root, 'certs')
    Path(path.certs).mkdir(exist_ok=True)
    path.config = os.path.join(root, 'config')
    path.lists = os.path.join("config", "lists")
    path.others = os.path.join("config", "others")
    path.scanners = os.path.join(root, 'scanners')
    path.fingprints = os.path.join(root, "fingerprints")
    path.output = os.path.join(root, "output")
    Path(path.output).mkdir(exist_ok=True)
    
def initKb():
    KB['continue'] = False  # 线程一直继续
    KB['registered'] = dict()  # 注册的漏洞插件列表
    KB['fingerprint'] = dict()  # 注册的指纹插件列表
    KB['task_queue'] = Queue()  # 初始化队列
    KB["spiderset"] = SpiderSet()  # 去重复爬虫
    KB['start_time'] = time.time()  # 开始时间
    KB["lock"] = threading.Lock()  # 线程锁
    KB["running_plugins"] = dict() # 运行中的插件统计
    KB['finished'] = 0  # 完成数量
    KB["result"] = 0  # 结果数量
    KB["running"] = 0  # 正在运行数量
    KB["request"] = 0 # 请求数量
    KB["request_fail"] = 0 # 请求失败数量
    KB["output"] = OutPut() # 报告信息
    KB.reverse_running_server = list() # 运行的反连服务
    KB.waf_detecting = list() # 限制单线程检测WAF

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
    dataToStdout(f"\n{colors.y}Loaded Plugins:{colors.e}")
    dataToStdout(table)
    dataToStdout(f"Total plugins: {colors.y}{len(KB['registered']) - 1}{colors.e}\n")
    """列出所有模糊测试字典"""
    if not hasattr(conf, "lists") or not conf.lists:
        logger.warning("No fuzz dictionaries loaded.")
        return
    table = PrettyTable()
    table.field_names = ["Dictionary Name", "Entry Count"]
    table.align["Dictionary Name"] = "l"
    for name, entries in conf.lists.items():
        table.add_row([name, len(entries)])
    dataToStdout(f"\n{colors.y}Loaded Fuzz Dictionaries:{colors.e}")
    dataToStdout(table)
    dataToStdout(f"Total dictionaries: {colors.y}{len(conf.lists)}{colors.e}\n")

def initPlugins():
    if conf.command == "list" or conf.get("redis_server"):
        conf.scanner_folder = ["PerFile", "PerFolder", "PerServer"]
    require_reverse_list = []
    # 加载loader
    loader_path = os.path.join(path.scanners, "loader.py")
    if os.path.exists(loader_path):
        try:
            loader_mod = load_file_to_module(loader_path)
            loader_instance = loader_mod.Z0SCAN()
            loader_instance.checkImplemennted()
            setattr(loader_instance, 'type', 'loader')
            setattr(loader_instance, 'path', 'loader.py')
            setattr(loader_instance, 'name', 'loader')
            KB["registered"]["loader"] = loader_instance
            logger.info("Loader plugin loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load loader: {e}")
            raise
    else:
        logger.error("Loader file not found at: {}".format(loader_path))
        raise FileNotFoundError("Loader plugin is required but not found")
    # 加载漏洞扫描插件
    for _dir in conf.scanner_folder:
        if _dir not in ["PerFile", "PerFolder", "PerServer"]:
            logger.error(f"Can't load plugins from {_dir}.")
            continue
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            for _ in files:
                filename = os.path.join(root, _)
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    if conf.get("load") and conf.get("load") != [] != []:
                        if mod.name not in conf.get("load") and conf.get("load") != []:
                            continue
                    if mod.risk not in conf.risk:
                        if conf.get("load") and conf.get("load") != [] != []:
                            logger.warning(f"Plugin {mod.name} can't be loaded because of risk.")
                        continue
                    plugin_type = os.path.split(root)[1]
                    relative_path = ltrim(filename, path.root)
                    if getattr(mod, 'type', None) is None:
                        setattr(mod, 'type', plugin_type)
                    if getattr(mod, 'path', None) is None:
                        setattr(mod, 'path', relative_path)
                    if conf.command == "reverse_client":
                        try:
                            if mod.require_reverse is True:
                                require_reverse_list.append(mod.name)
                                continue
                        except:
                            pass
                    KB["registered"][mod.name] = mod
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
    if not require_reverse_list == []:
        logger.info(f'Skip scanner plugins that require of reverse: {colors.y}{require_reverse_list}{colors.e}')
    if not conf.command == "list":
        logger.info(f'Load scanner plugins: {colors.y}{len(KB["registered"])-1}{colors.e}')
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
                logger.error("Filename: {} load faild, not function 'fingerprint'".format(filename))
                continue
            if name not in KB["fingerprint"]:
                KB["fingerprint"][name] = []
            KB["fingerprint"][name].append(mod)
            num += 1
    if not conf.command == "list":
        logger.info(f'Load fingerprint plugins: {colors.y}{num}{colors.e}')
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
    # server_addr
    if isinstance(conf["server_addr"], str):
        if ":" in conf["server_addr"]:
            splits = conf["server_addr"].split(":", 2)
            conf["server_addr"] = tuple([splits[0], int(splits[1])])
        else:
            conf["server_addr"] = tuple([conf["server_addr"], conf.default_proxy_port])
    # proxy
    if isinstance(conf["proxy"], str):
        if "://" in conf["proxy"]:
            method, ip = conf["proxy"].split("://")
            conf["proxies"] = {
                method.lower(): [ip]
            }
        else:
            from lib.proxy.autoproxy import AutoProxy
            conf["proxies"] = AutoProxy().import_proxies(conf["proxy"])
    # user-agent
    if conf.random_agent:
        conf.agent = random_UA()
    else:
        conf.agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101'
    if conf.get("server_addr"):
        conf.pause_upload = False # 暂停提交扫描任务

def _init_stdout():
    logger.info(f"Current WorkDir: {path.root}")
    logger.info(f"Number of Threads: {conf.threads} / {conf.plugin_threads}")
    logger.info(f"Scan Level: [#{conf.level}]")
    logger.info(f"Scan Risk: {conf.risk}")
    if conf.smartscan["enable"]:
        message = chat("API validity verification: If you can receive this message, please reply 'OK'")
        if message is None:
            # message为None时chat函数会警告
            sys.exit(0)
        elif "ok" in message.lower():
            logger.info("Connect to AI model: {}[OK]".format(conf.smartscan_selector["model"]))
        else:
            logger.info("AI return message is not True!")
            sys.exit(0)
    if conf.ignore_waf:
        logger.info(f'Ignore WAF Status: True')
    if conf.ignore_fingerprint:
        logger.info(f'Ignore Fingerprints Status: True')
    # 不扫描网址
    if len(conf["excludes"]):
        logger.info("Skip Scan: {}".format(repr(conf["excludes"])))
    if conf.get("load") and conf.get("load") != []:
        logger.info("Load Plugins: {}".format(repr(conf.get("load") and conf.get("load") != [])))
    if conf.html:
        logger.info("HTML Report Path: {}".format(KB.output.get_html_filename()))
    logger.info("JSON Report Path: {}".format(KB.output.get_filename()))

def _commands(v):
    if conf.command == "scan":
        return
    if v == "console":
        if conf.command == "console":
            try:
                client = Client(port=conf.console_port)
                while True:
                    msg = input(f"[{colors.m}CMD{colors.e}] Send to server >> ")
                    if msg.lower() == 'exit':
                        break
                    response = client.send_message(msg)
                    if response:
                        logger.info(f"{colors.br}{response}{colors.e}\n", showtime=False)
            except:
                client.close()
        else: return
    if v == "dbcmd":
        if conf.command == "dbcmd":
            try:
                while True:
                    cmd = input(f"[{colors.m}CMD{colors.e}] SQL Command ('exit' to quit) >> ")
                    if cmd.lower() == 'exit':
                        break
                    logger.info(f"{colors.br}{execute_sqlite_command(cmd)}{colors.e}\n", showtime=False)
            except Exception as e:
                logger.error(e, showtime=False)
        else: return
    if v == "reverse":
        if conf.command == "reverse":
            from lib.core.reverse import reverse_main
            reverse_main()
        else: return
    if v == "list":
        if conf.command == "list":
            _list()
        else: return
    if v == "version":
        if conf.command == "version":
            sys.exit(0)
        return
    if v == "update":
        if conf.command == "update":
            updater = AutoUpdater("JiuZero/z0scan", VERSION)
            updater.main()
            sys.exit(0)
        else:
            updater = AutoUpdater("JiuZero/z0scan", VERSION)
            update_info = updater.check_for_updates()
            if update_info:
                logger.info(f"Discover a new version: {update_info['version']}")
                logger.info(f"Updated content: {update_info['body']}")
        return
    sys.exit(0)

def _cleanup_update_backups():
    """清理可能残留的更新备份文件"""
    try:
        if getattr(sys, 'frozen', False):
            current_dir = os.path.dirname(sys.executable)
            exe_name = os.path.basename(sys.executable)
            backup_file = os.path.join(current_dir, f"{exe_name}.backup")
            backup_dir = os.path.join(current_dir, "backup")
            # 清理单个备份文件
            if os.path.exists(backup_file):
                try:
                    os.remove(backup_file)
                    logger.info("The remaining backup files have been cleared")
                except Exception as e:
                    logger.error(f"Failed to clean up the backup file: {e}")
            # 清理备份目录
            if os.path.exists(backup_dir):
                try:
                    if not os.listdir(backup_dir):
                        os.rmdir(backup_dir)
                        logger.info("The empty backup directory has been cleared")
                    else:
                        for file in os.listdir(backup_dir):
                            if file.endswith('.backup'):
                                try:
                                    os.remove(os.path.join(backup_dir, file))
                                except Exception:
                                    pass
                        if not os.listdir(backup_dir):
                            os.rmdir(backup_dir)
                            logger.info("The backup directory has been cleared")
                except Exception as e:
                    logger.error(f"Failed to clean up the backup directory: {e}")
    except Exception as e:
        logger.error(f"An error occurred while cleaning up the backup files: {e}")

def check_update():
    try:
        updater = AutoUpdater("JiuZero/z0scan", VERSION)
        update_info = updater.check_for_updates(force=True)
        if update_info:
            logger.info(f"{VERSION} -> {update_info['version']}", origin="updater")
            logger.info(f"Desc: {update_info['body']}", origin="updater")
    except Exception as e:
        logger.error("Check for version update error: ", str(e))
        
def init(root, cmdline):
    cinit(autoreset=True)
    setPaths(root) # 设置工作路径
    initKb() # 初始化KB
    dataToStdout(banner) # version & logo
    _merge_options(cmdline) # 合并命令行与config中的参数
    _commands("version")
    _cleanup_update_backups()
    _commands("update")
    _commands("console")
    initdb(root) # 初始化数据库
    _commands("dbcmd")
    _commands("reverse")
    initPlugins() # 初始化插件
    _commands("list")
    _set_conf() # 按照设置配置
    _init_stdout() # 打印初始化后的一些配置信息
    patch_all() # requests全局补丁
    ipv6_patch() # ipv6补丁
    if conf.get("redis_client") or conf.get("redis_server"):
        from lib.core.red import set_conn, cleanred
        set_conn() # 连接到redis
    if conf.get("clean_redis"):
        from lib.core.red import set_conn, cleanred
        cleanred() # 清理redis队列
    if conf.get("reverse_client"):
        check_reverse()