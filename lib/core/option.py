#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero/z0scan

import os, sys
import threading
import json, re
import time
from queue import Queue
import config
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
from lib.patch.requests_patch import patch_all
from lib.patch.ipv6_patch import ipv6_patch
from prettytable import PrettyTable
from lib.core.aichat import chat
from pathlib import Path
from lib.core.updater import check_update
from lib.core.fingers import Fcount, Wcount
from lib.core.thirdpart import API

def setPaths(root):
    path.root = root
    path.certs = os.path.join(root, 'certs')
    Path(path.certs).mkdir(exist_ok=True)
    path.dicts = os.path.join("dicts")
    path.helper = os.path.join("helper")
    path.data = os.path.join("data")
    path.scanners = os.path.join(root, 'scanners')
    path.temp = os.path.join(root, "temp")
    Path(path.temp).mkdir(exist_ok=True)
    path.output = os.path.join(root, "output")
    path.fingerprints = os.path.join(root, "fingerprints")
    Path(path.output).mkdir(exist_ok=True)
    
def initKb():
    KB['continue'] = False  # 线程一直继续
    KB['registered'] = dict()  # 注册的插件列表
    KB['portscan'] = dict()  # 注册的端口漏洞插件信息统计
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
    KB["reverse_running_server"] = list() # 运行的反连服务
    KB["waf_detecting"] = list() # 限制单线程检测WAF
    KB["pause_taskrun"] = False # 暂停任务（流量会正常转发到队列中）
    
def _list():
    """列出所有已注册的Scanners信息"""
    if "registered" not in KB or not KB["registered"]:
        logger.warning("No scanners loaded.")
        return
    table = PrettyTable()
    table.field_names = ["Name", "Description", "Risk Level"]
    table.align["Name"] = "l"
    table.align["Description"] = "l"
    for plugin_name, plugin_instance in KB["registered"].items():
        if plugin_name == "loader":
            continue
        name = getattr(plugin_instance, "name", "N/A")
        desc = getattr(plugin_instance, "desc", "N/A")
        risk = getattr(plugin_instance, "risk", "N/A")
        table.add_row([
            name,
            desc,
            risk,
        ])
    dataToStdout(f"\n{colors.y}Loaded Scanners: {colors.e}")
    dataToStdout(table)

def initPlugins():
    from lib.core.data import path
    require_reverse_list = []
    require_risk_list = []
    # 加载模糊字典
    conf.dicts = dict()
    for root, dirs, files in os.walk(path.dicts):
        files = list(filter(lambda x: x.endswith('.txt'), files))
        for _ in files:
            name = os.path.splitext(_)[0]
            file = os.path.join(path.dicts, _)
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = [line.strip() for line in f.readlines() if line.strip()]
                    # TODO: replace
                    conf.dicts[name] = content
            except Exception as e:
                logger.warning(f'Error loading list {file}: {str(e)}')
    # 优先加载loader
    loader_path = os.path.join(path.scanners, "loader.py")
    if os.path.exists(loader_path):
        try:
            loader_mod = load_file_to_module(loader_path)
            loader_instance = loader_mod.Z0SCAN()
            loader_instance.checkImplemennted()
            setattr(loader_instance, 'type', 'loader')
            setattr(loader_instance, 'path', loader_path)
            setattr(loader_instance, 'name', 'loader')
            KB["registered"]["loader"] = loader_instance
        except Exception as e:
            logger.error(f"Failed to load loader: {e}")
            raise
    else:
        logger.error("Loader file not found at: {}".format(loader_path))
        raise FileNotFoundError("Loader plugin is required but not found")
    # 加载漏洞扫描插件
    for _dir in ["PerPage", "PerDir", "PerDomain"]:
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            for _ in files:
                filename = os.path.join(root, _)
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    plugin_key = os.path.splitext(_)[0]
                    if conf.get("enable", []) != []:
                        if plugin_key not in conf.get("enable", []):
                            continue
                    if plugin_key in conf.get("disable", []):
                        continue
                    if not mod.risk in conf.risk:
                        require_risk_list.append(plugin_key)
                        continue
                    if conf.command != "reverse_client":
                        try:
                            if mod.require_reverse is True:
                                require_reverse_list.append(plugin_key)
                                continue
                        except:
                            pass
                    plugin_type = os.path.split(root)[1]
                    relative_path = ltrim(filename, path.root)
                    if getattr(mod, 'type', None) is None:
                        setattr(mod, 'type', plugin_type)
                    if getattr(mod, 'path', None) is None:
                        setattr(mod, 'path', relative_path)
                    KB["registered"][plugin_key] = mod
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
    for _dir in ["PerHost"]:
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            for _ in files:
                filename = os.path.join(root, _)
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    plugin_key = os.path.splitext(_)[0]
                    if conf.get("enable", []) != []:
                        if plugin_key not in conf.get("enable", []):
                            continue
                    if plugin_key in conf.get("disable", []):
                        continue
                    if not mod.risk in conf.risk:
                       require_risk_list.append(plugin_key)
                       continue
                    plugin_type = os.path.split(root)[1]
                    relative_path = ltrim(filename, path.root)
                    if getattr(mod, 'type', None) is None:
                        setattr(mod, 'type', plugin_type)
                    if getattr(mod, 'path', None) is None:
                        setattr(mod, 'path', relative_path)
                    """
                    ports = [23]
                    fingers = ["connection refused by remote host.", "^SSH-"]
                    """
                    KB["portscan"][plugin_key] = (mod.ports, mod.fingers)
                    KB["registered"][plugin_key] = mod
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
                
    if not require_reverse_list == []:
        logger.warning(f'Skip Scanners (Require Reverse): {colors.y}{require_reverse_list}{colors.e}')
    if not require_risk_list == []:
        logger.warning(f'Skip Scanners (Require Risk): {colors.y}{require_risk_list}{colors.e}')
    logger.info(f'Load Scanners: {colors.y}{len(KB["registered"])-1}{colors.e}')
    logger.info(f'Load Fingers: FINGER {colors.y}{Fcount()}{colors.e} | WAF {colors.y}{Wcount()}{colors.e}')
    logger.info(f'Load Dicts: {colors.y}{len(conf.dicts)}{colors.e}')

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

def import_proxies_from_file(file_path: str):
    """
    从文件中导入代理并返回字典
    等价于 AutoProxy.import_proxies 的实现：
      - JSON: [{"url": "http://1.2.3.4:8080", "protocol": "http"}, {"ip": "1.2.3.4", "port": 8080, "protocol": "socks5"}]
      - 文本: 每行一种格式：
          http://1.2.3.4:8080
          socks5://1.2.3.4:1080
          http,1.2.3.4:8080
    规则：
      - https 归并为 http
      - 仅接受形如 ip:port 的地址
    """
    proxies_by_protocol = {'http': [], 'socks4': [], 'socks5': []}
    valid_parse_protocols = {'http', 'https', 'socks4', 'socks5'}
    try:
        _, ext = os.path.splitext(file_path)
        if ext.lower() == '.json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        url = item.get('url')
                        protocol = item.get('protocol', 'http').lower()
                        if url:
                            m = re.match(r'(\w+)://(.+)', url)
                            if m:
                                protocol, proxy = m.groups()
                            else:
                                proxy = url
                        else:
                            proxy = f"{item.get('ip')}:{item.get('port')}"
                        if protocol == 'https':
                            protocol = 'http'
                        if protocol in proxies_by_protocol:
                            proxies_by_protocol[protocol].append(proxy)
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    protocol, proxy_address = 'http', line
                    m = re.match(r'(\w+)://(.+)', line)
                    if m:
                        proto_part, proxy_part = m.groups()
                        if proto_part.lower() in valid_parse_protocols:
                            proxy_address = proxy_part
                            protocol = 'http' if proto_part.lower() == 'https' else proto_part.lower()
                    elif ',' in line:
                        parts = [p.strip().lower() for p in line.split(',', 1)]
                        if len(parts) == 2 and parts[0] in valid_parse_protocols:
                            proxy_address, protocol = parts[1], 'http' if parts[0] == 'https' else parts[0]
                    if protocol in proxies_by_protocol and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', proxy_address):
                        proxies_by_protocol[protocol].append(proxy_address)
        total_imported = sum(len(v) for v in proxies_by_protocol.values())
        if total_imported == 0:
            logger.error(f"No found proxy lines in {file_path}.")
            sys.exit(0)
        logger.info(f"Success import {total_imported} proxys.")
        return proxies_by_protocol
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(0)

def _set_conf():
    # server_addr
    if conf.get("server_addr", False):
        if ":" in conf["server_addr"]:
            splits = conf["server_addr"].split(":", 2)
            conf["server_addr"] = tuple([splits[0], int(splits[1])])
        else:
            conf["server_addr"] = tuple([conf["server_addr"], conf.default_proxy_port])
    # proxy
    if conf.get("proxy", False):
        if "://" in conf["proxy"]:
            method, ip = conf["proxy"].split("://")
            conf["proxies"] = {
                method.lower(): [ip]
            }
        else:
            conf["proxies"] = import_proxies_from_file(conf["proxy"])
    # user-agent
    if conf.get("random_agent", False):
        conf.agent = random_UA()
    else:
        conf.agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101'
    if conf.get("server_addr", False):
        conf.pause_scanners = False # 仅队列不扫描

def _init_stdout():
    logger.info(f"Threads: TASK {colors.y}{conf.threads}{colors.e} | SCANNER {colors.y}{conf.plugin_threads}{colors.e}")
    logger.info(f"Scan Level: {colors.y}{conf.level}{colors.e}")
    logger.info(f"Scan Risk: {colors.y}{conf.risk}{colors.e}")
    if conf.smartscan["enable"]:
        message = chat("API validity verification: If you can receive this message, please reply 'OK'")
        if message is None:
            # message为None时chat函数会警告
            sys.exit(0)
        elif "ok" in message.lower():
            logger.info("Connect to AI model: {}[OK]".format(conf.smartscan["model"]))
        else:
            logger.error("AI return message is not True!")
            sys.exit(0)
    if conf.ignore_waf:
        logger.info(f'Ignore WAF Status: {colors.y}True{colors.e}')
    if len(conf["includes"]):
        logger.info(f"Includes: {colors.y}{repr(conf['includes'])}{colors.e}")
    if len(conf["excludes"]):
        logger.info(f"Excludes: {colors.y}{repr(conf['excludes'])}{colors.e}")
    if conf.get("load") and conf.get("load") != []:
        logger.info(f"Load Plugins: {colors.y}{repr(conf.get('load') and conf.get('load') != [])}{colors.e}")
    if conf.html:
        logger.info(f"HTML Report: {colors.y}{KB.output.get_html_filename()}{colors.e}")
    logger.info(f"JSON Report: {colors.y}{KB.output.get_filename()}{colors.e}")
    logger.info(f"TXT Record: {colors.y}{KB.output.get_txt_filename()}{colors.e}")
    logger.info(f"Database Record: {colors.y}{KB.output.get_db_filename()}{colors.e}")

def _commands(v):
    if conf.command == "scan":
        return
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
    if v == "clean_redis":
        if conf.get("clean_redis"):
            from lib.core.red import set_conn, cleanred
            cleanred() # 清理redis队列
    if v == "crawler":
        if conf.command == "crawler":
            from lib.core.crawler import CrawlerConfig, CrawlerMode, UniversalCrawler
            from lib.core.common import random_UA
            from crawlee.crawlers import BeautifulSoupCrawlingContext, PlaywrightCrawlingContext
            
            # 处理起始 URLs
            start_urls = []
            if conf.get("url"):
                start_urls.append(conf.get("url"))
            if conf.get("url_file"):
                try:
                    with open(conf.get("url_file"), 'r', encoding='utf-8') as f:
                        file_urls = [line.strip() for line in f if line.strip()]
                        start_urls.extend(file_urls)
                except Exception as e:
                    logger.error(f"Failed to read URL file: {e}")
                    sys.exit(1)
            
            if not start_urls:
                logger.error("No URLs provided for crawling")
                sys.exit(1)
            
            # 处理 User-Agent
            user_agent = None
            if conf.get("random_agent"):
                user_agent = random_UA()
            
            # 处理代理
            proxy = conf.get("proxy")
            
            # 处理输出目录
            output_dir = conf.get("output", "./crawler_output")
            
            logger.info(f"Crawler Mode: {colors.y}{conf.get('mode', 'beautifulsoup').upper()}{colors.e}")
            logger.info(f"Start URLs: {colors.y}{len(start_urls)}{colors.e}")
            logger.info(f"Max Requests: {colors.y}{conf.get('max_requests', 100)}{colors.e}")
            logger.info(f"Max Concurrency: {colors.y}{conf.get('max_concurrency', 10)}{colors.e}")
            logger.info(f"Timeout: {colors.y}{conf.get('timeout', 30)}s{colors.e}")
            
            if proxy:
                logger.info(f"Proxy: {colors.y}{proxy}{colors.e}")
            if user_agent:
                logger.info(f"User-Agent: {colors.y}Random{colors.e}")
            if conf.get("includes"):
                logger.info(f"Includes: {colors.y}{conf.get('includes')}{colors.e}")
            if conf.get("excludes"):
                logger.info(f"Excludes: {colors.y}{conf.get('excludes')}{colors.e}")
            
            logger.info(f"Output Dir: {colors.y}{output_dir}{colors.e}")
            
            # 定义请求处理器
            if conf.get("mode", "beautifulsoup").lower() == "beautifulsoup":
                async def crawler_handler(context: BeautifulSoupCrawlingContext):
                    try:
                        context.log.info(f'Crawling: {context.request.url}')
                        
                        soup = context.soup
                        
                        # 提取数据
                        data = {
                            'url': context.request.url,
                            'title': soup.title.string if soup.title else '',
                            'status_code': context.http_response.status_code if hasattr(context, 'http_response') else 200,
                        }
                        
                        # 可选：提取更多信息
                        if conf.get("extract_h1", True):
                            data['h1_tags'] = [h1.get_text(strip=True) for h1 in soup.find_all('h1')]
                        
                        # 保存数据
                        await context.push_data(data)
                        
                        # URL过滤逻辑
                        def should_crawl_url(url):
                            if conf.get("includes"):
                                if not any(keyword in url for keyword in conf.get("includes")):
                                    return False
                            if conf.get("excludes"):
                                if any(keyword in url for keyword in conf.get("excludes")):
                                    return False
                            return True
                        
                        # 添加新链接到队列
                        if should_crawl_url(context.request.url):
                            await context.enqueue_links()
                        
                    except Exception as e:
                        context.log.error(f'Error processing {context.request.url}: {str(e)}')
            else:
                async def crawler_handler(context: PlaywrightCrawlingContext):
                    try:
                        context.log.info(f'Crawling: {context.request.url}')
                        
                        page = context.page
                        await page.wait_for_load_state('networkidle')
                        
                        # 提取数据
                        data = {
                            'url': context.request.url,
                            'title': await page.title(),
                        }
                        
                        if conf.get("extract_h1", True):
                            h1_elements = await page.query_selector_all('h1')
                            data['h1_tags'] = [await h1.text_content() for h1 in h1_elements]
                        
                        await context.push_data(data)
                        
                        def should_crawl_url(url):
                            if conf.get("includes"):
                                if not any(keyword in url for keyword in conf.get("includes")):
                                    return False
                            if conf.get("excludes"):
                                if any(keyword in url for keyword in conf.get("excludes")):
                                    return False
                            return True
                        
                        if should_crawl_url(context.request.url):
                            await context.enqueue_links()
                        
                    except Exception as e:
                        context.log.error(f'Error processing {context.request.url}: {str(e)}')
            
            # 确定爬虫模式
            crawler_mode = (
                CrawlerMode.PLAYWRIGHT 
                if conf.get("mode", "beautifulsoup").lower() == "playwright" 
                else CrawlerMode.BEAUTIFULSOUP
            )
            
            # 创建爬虫配置
            crawler_config = CrawlerConfig(
                start_urls=start_urls,
                mode=crawler_mode,
                max_requests_per_crawl=conf.get("max_requests", 100),
                max_concurrency=conf.get("max_concurrency", 10),
                request_handler=crawler_handler,
                headless=conf.get("headless", True),
                browser_type=conf.get("browser_type", "chromium"),
                proxy=proxy,
                timeout=conf.get("timeout", 30),
                user_agent=user_agent,
                output_dir=output_dir,
                json_output=conf.get("json_output", True),
                min_delay=conf.get("min_delay", 1.0), 
                max_delay=conf.get("max_delay", 3.0),  
                verbose=conf.get("verbose", False), 
            )
            
            # 创建并运行爬虫
            try:
                logger.info("Starting crawler...")
                crawler = UniversalCrawler(crawler_config)
                crawler.run_sync()
                logger.info(f"{colors.g}Crawler finished successfully{colors.e}")
                logger.info(f"Results saved to: {colors.y}{output_dir}{colors.e}")
            except KeyboardInterrupt:
                logger.warning("Crawler interrupted by user")
            except Exception as e:
                logger.error(f"Crawler failed: {str(e)}")
                if conf.get("debug"):
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
    sys.exit(0)


def check_up():
    try:
        latest = check_update("JiuZero/z0scan", VERSION)
        if not latest is False:
            logger.info(f"Version update: {colors.r}{VERSION}{colors.e} -> {colors.r}{latest['latest_version']}{colors.e}", origin="updater")
            logger.info(f"Desc: {latest['html_url']}", origin="updater")
    except Exception as e:
        pass

def init(root, cmdline):
    cinit(autoreset=True)
    setPaths(root) # 设置工作路径
    initKb() # 初始化KB
    dataToStdout(banner) # version & logo
    check_up()
    _merge_options(cmdline) # 合并命令行与config中的参数
    _commands("version")
    _commands("crawler") # 初始化爬虫
    initdb() # 初始化数据库
    _commands("reverse")
    _commands("clean_redis")
    initPlugins() # 初始化插件
    _commands("list")
    _set_conf() # 按照设置配置
    KB["pocscan"] = API()
    _init_stdout() # 打印初始化后的一些配置信息
    patch_all() # requests全局补丁
    ipv6_patch() # ipv6补丁
    if conf.get("redis_client") or conf.get("redis_server"):
        from lib.core.red import set_conn, cleanred
        set_conn() # 连接到redis
    if conf.get("reverse_client"):
        check_reverse()