#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import subprocess
from typing import List, Dict, Optional
from lib.core.data import conf, path
from lib.core.log import logger


class Crawlergo:
    def __init__(self):
        config_info = []
        self.chrome_path = getattr(conf, 'chrome_path', None)
        self.crawlergo_path = getattr(path, 'crawlergo', 'crawlergo')
        options = {
            "max_tabs": getattr(conf, 'max_tab_count', 8),
            "max_crawled": getattr(conf, 'max_crawled_count', 200),
            "filter_mode": getattr(conf, 'filter_mode', "smart"),
        }
        if hasattr(self, 'crawlergo_path'):
            config_info.append(f"Crawlergo path: {self.crawlergo_path}")
        if self.chrome_path:
            config_info.append(f"Chrome path: {self.chrome_path}")
        config_info.append(f"Max tabs: {options['max_tabs']}")
        config_info.append(f"Max crawled: {options['max_crawled']}")
        config_info.append(f"Filter mode: {options['filter_mode']}")
        # 添加代理配置
        if hasattr(conf, "proxy"):
            options["--request-proxy"] = conf.proxy
        if hasattr(conf, 'server_addr'):
            options["push_to_proxy"] = f"http://{conf.server_addr[0]}:{conf.server_addr[1]}"
        if hasattr(conf, 'custom_headers') and conf.custom_headers:
            options["headers"] = conf.custom_headers
            config_info.append(f"Custom headers: {len(options['headers'])} headers")
        if hasattr(conf, 'custom_cookies') and conf.custom_cookies:
            options["cookies"] = conf.custom_cookies
            config_info.append(f"Custom cookies: {len(options['cookies'])} characters")
        if hasattr(conf, 'ignore_url_keywords') and conf.ignore_url_keywords:
            options["ignore_keywords"] = conf.ignore_url_keywords
            if isinstance(options["ignore_keywords"], list):
                config_info.append(f"Ignore keywords: {len(options['ignore_keywords'])} items")
            else:
                config_info.append(f"Ignore keywords: {options['ignore_keywords']}")
        if hasattr(conf, 'tab_run_timeout'):
            options["tab_run_timeout"] = conf.tab_run_timeout
            config_info.append(f"Tab timeout: {options['tab_run_timeout']}s")
        if hasattr(conf, 'wait_dom_timeout'):
            options["wait_dom_timeout"] = conf.wait_dom_timeout
            config_info.append(f"DOM timeout: {options['wait_dom_timeout']}s")
        if hasattr(conf, 'push_pool_max'):
            options["push_pool_max"] = conf.push_pool_max
            config_info.append(f"Push pool max: {options['push_pool_max']}")
        if hasattr(conf, 'crawler_fuzz') and conf.crawler_fuzz.get("enable") is True:
            options["fuzz_path"] = True
            if conf.crawler_fuzz.get("path"):
                options["fuzz_path_dict"] = conf.crawler_fuzz["path"]
            config_info.append(f"Fuzz path: enabled")
            config_info.append(f"Fuzz dict: {options['fuzz_path_dict']}")
        if hasattr(conf, 'crawler_robots_path') and conf.crawler_robots_path is True:
            options["robots_path"] = True
            config_info.append(f"Parse robots.txt: enabled")
        if hasattr(conf, 'crawler_headless') and conf.crawler_headless is False:
            options["no_headless"] = True
            config_info.append(f"Headless mode: disabled")
        else:
            config_info.append(f"Headless mode: enabled")
        logger.info(f"Crawler configuration: {', '.join(config_info)}")
        self.options = options
        
    def crawl(self, target_url: str) -> List[Dict]:
        # Build command
        cmd = self._build_command(target_url)
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
    
    def _build_command(self, target_url: str) -> List[str]:
        """构建 crawlergo 命令行参数"""
        cmd = [self.crawlergo_path]
        # Chrome path
        if self.chrome_path:
            cmd.extend(["-c", self.chrome_path])
        # Output mode
        cmd.extend(["-o", "json"])
        # Optional parameters
        if self.options.get("max_tabs"):
            cmd.extend(["-t", str(self.options["max_tabs"])])
        if self.options.get("max_crawled"):
            cmd.extend(["-m", str(self.options["max_crawled"])])
        # Filter mode
        filter_mode = self.options.get("filter_mode", "smart")
        cmd.extend(["-f", filter_mode])
        # Proxy
        if self.options.get("proxy"):
            cmd.extend(["--request-proxy", self.options["proxy"]])
        # Custom headers
        if self.options.get("headers"):
            cmd.extend(["--custom-headers", json.dumps(self.options["headers"])])
        # Cookies
        if self.options.get("cookies"):
            cmd.extend(["--custom-cookies", self.options["cookies"]])
        # Ignore URL keywords
        if self.options.get("ignore_keywords"):
            if isinstance(self.options["ignore_keywords"], list):
                for keyword in self.options["ignore_keywords"]:
                    cmd.extend(["-iuk", keyword])
            else:
                cmd.extend(["-iuk", self.options["ignore_keywords"]])
        # Additional crawlergo options
        if self.options.get("tab_run_timeout"):
            cmd.extend(["--tab-run-timeout", f"{self.options['tab_run_timeout']}s"])
        if self.options.get("wait_dom_timeout"):
            cmd.extend(["--wait-dom-content-loaded-timeout", f"{self.options['wait_dom_timeout']}s"])
        if self.options.get("push_to_proxy"):
            cmd.extend(["--request-proxy", str(self.options["push_to_proxy"])])
        if self.options.get("push_pool_max"):
            cmd.extend(["--push-pool-max", str(self.options["push_pool_max"])])
        # Fuzz options
        if self.options.get("fuzz_path"):
            cmd.append("--fuzz-path")
        if self.options.get("fuzz_path_dict"):
            cmd.extend(["--fuzz-path-dict", self.options["fuzz_path_dict"]])
        # Robots.txt parsing
        if self.options.get("robots_path"):
            cmd.append("--robots-path")
        # Headless mode
        if self.options.get("no_headless"):
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