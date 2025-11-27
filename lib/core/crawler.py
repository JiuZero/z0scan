from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
import asyncio
import json
import os
import random
from pathlib import Path
from datetime import timedelta
from lib.core.data import path
from crawlee.crawlers import (
    BeautifulSoupCrawler,
    PlaywrightCrawler,
)
from crawlee.storages import Dataset
from crawlee.http_clients import HttpxHttpClient


class CrawlerMode(Enum):
    """爬虫模式"""
    BEAUTIFULSOUP = "beautifulsoup"
    PLAYWRIGHT = "playwright"


@dataclass
class CrawlerConfig:
    """爬虫配置"""
    start_urls: List[str]
    mode: CrawlerMode = CrawlerMode.BEAUTIFULSOUP
    max_requests_per_crawl: Optional[int] = 100
    max_concurrency: int = 10
    request_handler: Optional[Callable] = None

    # Playwright 特定配置
    headless: bool = True
    browser_type: str = "chromium"

    # 请求配置
    proxy: Optional[str] = None
    timeout: int = 30
    user_agent: Optional[str] = None

    # 反反爬虫配置
    retry_on_blocked: bool = True
    max_session_rotations: int = 5
    max_request_retries: int = 0

    # Crawlee 高级配置
    use_session_pool: bool = True
    keep_alive: bool = False
    configure_logging: bool = True
    request_handler_timeout: Optional[timedelta] = None 

    # 延迟配置
    min_delay: float = 1.0  # 最小延迟（秒）
    max_delay: float = 3.0  # 最大延迟（秒）

    # 日志配置
    verbose: bool = False

    # 输出配置
    output_dir: str = path.temp
    json_output: bool = True


class UniversalCrawler:
    """通用爬虫类"""

    # 常用的 User-Agent 列表
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]

    def __init__(self, config: CrawlerConfig):
        self.config = config
        self.crawler = None
        self.results: List[Dict[str, Any]] = []
        self._setup_output_dir()

    def _setup_output_dir(self):
        """设置输出目录"""
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)

    def _get_random_user_agent(self) -> str:
        """获取随机 User-Agent"""
        if self.config.user_agent:
            return self.config.user_agent
        return random.choice(self.USER_AGENTS)

    def _get_proxy_config(self) -> Optional[str]:
        """解析代理配置"""
        if not self.config.proxy:
            return None

        proxy_url = self.config.proxy
        if not proxy_url.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            proxy_url = f'http://{proxy_url}'

        return proxy_url

    def _get_additional_headers(self) -> Dict[str, str]:
        """获取额外的 HTTP 头"""
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

    async def _delay_between_requests(self):
        """请求之间的随机延迟"""
        delay = random.uniform(self.config.min_delay, self.config.max_delay)
        await asyncio.sleep(delay)

    def _wrap_request_handler(self, handler: Callable) -> Callable:
        """包装请求处理器以添加延迟"""
        async def wrapped_handler(context):
            # 请求前延迟
            await self._delay_between_requests()
            # 执行原始处理器
            result = await handler(context)
            return result
        return wrapped_handler

    def _setup_crawler(self):
        """根据配置初始化爬虫"""
        # 基础配置
        crawler_kwargs = {
            'max_requests_per_crawl': self.config.max_requests_per_crawl,
            'request_handler_timeout': (
                self.config.request_handler_timeout
                or timedelta(seconds=self.config.timeout)
            ),
            'max_session_rotations': self.config.max_session_rotations,
            'max_request_retries': self.config.max_request_retries,
            'retry_on_blocked': self.config.retry_on_blocked,
        }

        # 根据模式创建对应的爬虫
        if self.config.mode == CrawlerMode.PLAYWRIGHT:
            # Playwright 特定配置
            playwright_options = {
                'headless': self.config.headless,
                'browser_type': self.config.browser_type,
            }

            # 添加代理配置
            proxy_url = self._get_proxy_config()
            launch_options: Dict[str, Any] = {}
            if proxy_url:
                launch_options['proxy'] = {'server': proxy_url}

            # 添加其他浏览器启动选项
            launch_options['args'] = [
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--disable-web-security',
                '--no-sandbox',
                '--disable-logging',  # 禁用浏览器日志
            ]
            playwright_options['browser_launch_options'] = launch_options

            # 浏览器上下文配置
            context_options = {
                'user_agent': self._get_random_user_agent(),
                'viewport': {'width': 1920, 'height': 1080},
                'locale': 'en-US',
                'timezone_id': 'America/New_York',
                'extra_http_headers': self._get_additional_headers(),
            }
            playwright_options['browser_new_context_options'] = context_options

            crawler_kwargs.update(playwright_options)
            self.crawler = PlaywrightCrawler(**crawler_kwargs)

        else:
            # BeautifulSoup 配置 - 创建 HTTP 客户端
            http_client_kwargs: Dict[str, Any] = {
                'timeout': self.config.timeout,
                'follow_redirects': True,
            }

            # 添加代理
            proxy_url = self._get_proxy_config()
            if proxy_url:
                http_client_kwargs['proxies'] = proxy_url

            # 添加自定义头
            headers = {
                'User-Agent': self._get_random_user_agent(),
                **self._get_additional_headers(),
            }
            http_client_kwargs['headers'] = headers
            http_client = HttpxHttpClient(**http_client_kwargs)
            crawler_kwargs['http_client'] = http_client

            self.crawler = BeautifulSoupCrawler(**crawler_kwargs)
        if self.config.request_handler:
            wrapped_handler = self._wrap_request_handler(self.config.request_handler)
            self.crawler.router.default_handler(wrapped_handler)

    async def run(self):
        self._setup_crawler()
        try:
            await self.crawler.run(self.config.start_urls)
        except Exception as e:
            self.last_error = e

        # 如果需要 JSON 输出，导出数据
        if self.config.json_output:
            await self._export_results()

    async def _export_results(self):
        """导出爬取结果为 JSON"""
        try:
            dataset = await Dataset.open()
            data = await dataset.get_data()

            # 保存为 JSON
            output_file = os.path.join(
                self.config.output_dir,
                'crawler_results.json'
            )

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data.items, f, ensure_ascii=False, indent=2)

            # 保存 URL 列表
            txt_file = os.path.join(
                self.config.output_dir,
                'crawler_urls.txt'
            )
            with open(txt_file, 'w', encoding='utf-8') as f:
                for item in data.items:
                    f.write(f"{item.get('url', '')}\n")

            # 保存统计信息
            stats_file = os.path.join(
                self.config.output_dir,
                'crawler_stats.json'
            )
            stats = {
                'total_items': len(data.items),
                'unique_urls': len(set(item.get('url', '') for item in data.items)),
                'output_file': output_file,
                'txt_file': txt_file,
            }
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)

            return output_file

        except Exception as e:
            return None

    def run_sync(self):
        try:
            return asyncio.run(self.run())
        except Exception as e:
            self.last_error = e
            return None


def create_crawler(
    start_urls: List[str],
    mode: str = "beautifulsoup",
    max_requests: int = 100,
    max_concurrency: int = 10,
    request_handler: Optional[Callable] = None,
    headless: bool = True,
    browser_type: str = "chromium",
    proxy: Optional[str] = None,
    timeout: int = 30,
    user_agent: Optional[str] = None,
    output_dir: str = "./crawler_output",
    json_output: bool = True,
    retry_on_blocked: bool = True,
    max_session_rotations: int = 5,
    max_request_retries: int = 0,
    min_delay: float = 1.0,
    max_delay: float = 3.0,
    verbose: bool = False,
) -> UniversalCrawler:
    """快速创建爬虫"""
    crawler_mode = (
        CrawlerMode.PLAYWRIGHT
        if mode.lower() == "playwright"
        else CrawlerMode.BEAUTIFULSOUP
    )

    config = CrawlerConfig(
        start_urls=start_urls,
        mode=crawler_mode,
        max_requests_per_crawl=max_requests,
        max_concurrency=max_concurrency,
        request_handler=request_handler,
        headless=headless,
        browser_type=browser_type,
        proxy=proxy,
        timeout=timeout,
        user_agent=user_agent,
        output_dir=output_dir,
        json_output=json_output,
        retry_on_blocked=retry_on_blocked,
        max_session_rotations=max_session_rotations,
        max_request_retries=max_request_retries,
        min_delay=min_delay,
        max_delay=max_delay,
        verbose=verbose,
    )

    return UniversalCrawler(config)
