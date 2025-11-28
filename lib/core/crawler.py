#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import subprocess
from typing import List, Dict, Optional
from lib.core.data import conf, path
from lib.core.log import logger


class SimpleCrawlergo:
    def __init__(self, chrome_path: Optional[str] = None):
        self.chrome_path = chrome_path
        self.crawlergo_path = getattr(path, 'crawlergo', 'crawlergo')
    
    def crawl(self, target_url: str, **kwargs) -> List[Dict]:
        """
        爬取 URL 并返回请求列表
        
        参数:
            target_url: 要爬取的 URL
            **kwargs: 额外选项
            
        返回:
            请求字典列表
        """
        # Build command
        cmd = self._build_command(target_url, **kwargs)
        
        try:
            logger.debug(f"Executing crawlergo: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                logger.error(f"Crawlergo execution failed: {result.stderr}")
                return []
            
            # Parse output
            return self._parse_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error("Crawlergo execution timed out")
            return []
        except Exception as e:
            logger.error(f"Crawlergo execution error: {e}")
            return []
    
    def _build_command(self, target_url: str, **kwargs) -> List[str]:
        """构建 crawlergo 命令行参数"""
        cmd = [self.crawlergo_path]
        # Chrome path
        if self.chrome_path:
            cmd.extend(["-c", self.chrome_path])
        # Output mode
        cmd.extend(["-o", "json"])
        # Optional parameters
        if "max_tabs" in kwargs:
            cmd.extend(["-t", str(kwargs["max_tabs"])])
        else:
            cmd.extend(["-t", str(conf.get("max_tabs", 8))])
        if "max_crawled" in kwargs:
            cmd.extend(["-m", str(kwargs["max_crawled"])])
        else:
            cmd.extend(["-m", str(conf.get("max_crawled", 200))])
        # Filter mode
        filter_mode = kwargs.get("filter_mode", "smart")
        cmd.extend(["-f", filter_mode])
        # Proxy
        if "proxy" in kwargs and kwargs["proxy"]:
            cmd.extend(["--request-proxy", kwargs["proxy"]])
        elif conf.get("proxies", {}):
            # Use first available proxy
            proxy = next(iter(conf.get("proxies", {}).values()), [None])[0]
            if proxy:
                cmd.extend(["--request-proxy", proxy])
        # Custom headers
        if "headers" in kwargs and kwargs["headers"]:
            cmd.extend(["--custom-headers", json.dumps(kwargs["headers"])])
        # Cookies
        if "cookies" in kwargs and kwargs["cookies"]:
            cmd.extend(["--custom-cookies", kwargs["cookies"]])
        # Ignore URL keywords
        if "ignore_keywords" in kwargs and kwargs["ignore_keywords"]:
            if isinstance(kwargs["ignore_keywords"], list):
                for keyword in kwargs["ignore_keywords"]:
                    cmd.extend(["-iuk", keyword])
            else:
                cmd.extend(["-iuk", kwargs["ignore_keywords"]])
        # Additional crawlergo options
        if "tab_run_timeout" in kwargs:
            cmd.extend(["--tab-run-timeout", f"{kwargs['tab_run_timeout']}s"])
        if "wait_dom_timeout" in kwargs:
            cmd.extend(["--wait-dom-content-loaded-timeout", f"{kwargs['wait_dom_timeout']}s"])
        if "push_pool_max" in kwargs:
            cmd.extend(["--push-pool-max", str(kwargs["push_pool_max"])])
        # Fuzz options
        if kwargs.get("fuzz_path"):
            cmd.append("--fuzz-path")
        if "fuzz_path_dict" in kwargs and kwargs["fuzz_path_dict"]:
            cmd.extend(["--fuzz-path-dict", kwargs["fuzz_path_dict"]])
        # Robots.txt parsing
        if kwargs.get("robots_path") is True:
            cmd.append("--robots-path")
        # Headless mode
        if kwargs.get("no_headless") is True:
            cmd.append("--no-headless")
        # Target URL (last argument)
        cmd.append(target_url)
        return cmd
    
    def _parse_output(self, output: str) -> List[Dict]:
        """解析 crawlergo JSON 输出"""
        try:
            separator = "--[Mission Complete]--"
            if separator not in output:
                logger.warning("Crawlergo output may be incomplete")
                return []
            # Extract JSON part
            json_part = output.split(separator)[1].strip()
            result_dict = json.loads(json_part)
            # Return request list
            req_list = result_dict.get("req_list", [])
            logger.info(f"Crawlergo found {len(req_list)} requests")
            return req_list
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse crawlergo output: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing crawlergo output: {e}")
            return []


def crawl_url(target_url: str, **kwargs) -> List[str]:
    """
    简化函数，爬取 URL 并返回 URL 列表
    
    参数:
        target_url: 要爬取的 URL
        **kwargs: crawlergo 的额外选项
        
    返回:
        爬取过程中发现的 URL 列表
    """
    crawler = SimpleCrawlergo()
    requests = crawler.crawl(target_url, **kwargs)
    return [req.get("url", "") for req in requests if req.get("url")]


def crawl_with_auth(target_url: str, cookies: str, chrome_path: Optional[str] = None, **kwargs) -> List[str]:
    """
    带认证的 URL 爬取
    
    参数:
        target_url: 要爬取的 URL
        cookies: 认证用的 Cookie 字符串
        chrome_path: Chrome 可执行文件路径
        **kwargs: crawlergo 的额外选项
        
    返回:
        爬取过程中发现的 URL 列表
    """
    crawler = SimpleCrawlergo(chrome_path)
    kwargs["cookies"] = cookies
    requests = crawler.crawl(target_url, **kwargs)
    return [req.get("url", "") for req in requests if req.get("url")]


def start_crawler_from_conf(target_url: str, proxy_addr: Optional[str] = None) -> List[Dict]:
    """
    使用全局 conf 对象的配置启动爬虫
    
    参数:
        target_url: 要爬取的 URL
        proxy_addr: 代理服务器地址（可选，如未提供则使用 conf.server_addr）
        
    返回:
        请求字典列表
    """
    # 使用配置中的 Chrome 路径初始化爬虫
    chrome_path = getattr(conf, 'chrome_path', None)
    crawler = SimpleCrawlergo(chrome_path)
    
    # 从 conf 对象构建选项
    options = {
        "max_tabs": getattr(conf, 'max_tab_count', 8),
        "max_crawled": getattr(conf, 'max_crawled_count', 200),
        "filter_mode": getattr(conf, 'filter_mode', "smart"),
    }
    
    # 添加代理配置
    if proxy_addr:
        options["proxy"] = proxy_addr
    elif hasattr(conf, 'server_addr'):
        options["proxy"] = f"http://{conf.server_addr}"

    if hasattr(conf, 'custom_headers') and conf.custom_headers:
        options["headers"] = conf.custom_headers
    if hasattr(conf, 'custom_cookies') and conf.custom_cookies:
        options["cookies"] = conf.custom_cookies
    if hasattr(conf, 'ignore_url_keywords') and conf.ignore_url_keywords:
        options["ignore_keywords"] = conf.ignore_url_keywords
    if hasattr(conf, 'tab_run_timeout'):
        options["tab_run_timeout"] = conf.tab_run_timeout
    if hasattr(conf, 'wait_dom_timeout'):
        options["wait_dom_timeout"] = conf.wait_dom_timeout
    if hasattr(conf, 'push_pool_max'):
        options["push_pool_max"] = conf.push_pool_max
    if hasattr(conf, 'crawler_fuzz') and conf.crawler_fuzz.get("enable") is True:
        options["fuzz_path"] = True
        if conf.crawler_fuzz.get("path"):
            options["fuzz_path_dict"] = conf.crawler_fuzz["path"]
    if hasattr(conf, 'crawler_robots_path') and conf.crawler_robots_path is True:
        options["robots_path"] = True
    if hasattr(conf, 'crawler_headless') and conf.crawler_headless is False:
        options["no_headless"] = True
    
    # 执行爬取
    logger.info(f"Crawler target: {target_url}")
    if options.get("proxy"):
        logger.info(f"Crawler traffic will be proxied to: {options['proxy']}")
    config_info = []
    config_info.append(f"Max tabs: {options['max_tabs']}")
    config_info.append(f"Max crawled: {options['max_crawled']}")
    config_info.append(f"Filter mode: {options['filter_mode']}")
    
    if options.get("tab_run_timeout"):
        config_info.append(f"Tab timeout: {options['tab_run_timeout']}s")
    
    if options.get("wait_dom_timeout"):
        config_info.append(f"DOM timeout: {options['wait_dom_timeout']}s")
    
    if options.get("push_pool_max"):
        config_info.append(f"Push pool max: {options['push_pool_max']}")
    
    if options.get("headers"):
        config_info.append(f"Custom headers: {len(options['headers'])} headers")
    
    if options.get("cookies"):
        config_info.append(f"Custom cookies: {len(options['cookies'])} characters")
    
    if options.get("ignore_keywords"):
        if isinstance(options["ignore_keywords"], list):
            config_info.append(f"Ignore keywords: {len(options['ignore_keywords'])} items")
        else:
            config_info.append(f"Ignore keywords: {options['ignore_keywords']}")
    
    if options.get("fuzz_path"):
        config_info.append(f"Fuzz path: enabled")
        if options.get("fuzz_path_dict"):
            config_info.append(f"Fuzz dict: {options['fuzz_path_dict']}")
    
    if options.get("robots_path"):
        config_info.append(f"Parse robots.txt: enabled")
    
    if options.get("no_headless"):
        config_info.append(f"Headless mode: disabled")
    else:
        config_info.append(f"Headless mode: enabled")
    
    if hasattr(crawler, 'crawlergo_path'):
        config_info.append(f"Crawlergo path: {crawler.crawlergo_path}")
    
    if crawler.chrome_path:
        config_info.append(f"Chrome path: {crawler.chrome_path}")
    
    logger.info(f"Crawler configuration: {', '.join(config_info)}")
    
    return crawler.crawl(target_url, **options)