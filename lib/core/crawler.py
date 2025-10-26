#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from lib.core.log import logger
import threading
import queue
import time
from urllib.parse import urlparse, urljoin, parse_qsl
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from lib.core.settings import notAcceptedExt

class Crawler:
    """爬虫类，负责爬取网站页面"""
    
    def __init__(self, max_depth=2, threads=5, exclude_pattern=None, include_pattern=None):
        """
        初始化爬虫
        
        Args:
            http_client: HTTP客户端
            max_depth: 最大爬取深度
            threads: 线程数
            exclude_pattern: 排除URL模式
            include_pattern: 包含URL模式
        """
        self.max_depth = max_depth
        self.threads = threads
        self.exclude_pattern = exclude_pattern
        self.include_pattern = include_pattern
        
        # 已访问的URL
        self.visited_urls = set()
        
        # 待访问的URL队列
        self.url_queue = queue.Queue()
        
        # 存储爬取结果
        self.results = []
        
        # 线程锁
        self.lock = threading.Lock()
        
        # 线程池
        self.thread_pool = None
        
        # 记录每个页面的加载状态
        self.page_status = {}
        
        # 常见的静态资源文件扩展名
        self.static_extensions = notAcceptedExt
    
    def crawl(self, base_url):
        """
        爬取指定的网站
        
        Args:
            base_url: 基础URL
            
        Returns:
            list: 爬取结果，包含页面信息
        """
        logger.info(f"Start crawl on {base_url}")
        
        # 重置状态
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.results = []
        self.page_status = {}
        
        # 解析基础URL
        parsed_base_url = urlparse(base_url)
        self.base_domain = parsed_base_url.netloc
        
        # 添加基础URL到队列
        self.url_queue.put((base_url, 0))  # (url, depth)
        
        # 创建线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=self.threads)
        
        # 创建并启动爬虫线程
        workers = []
        for _ in range(self.threads):
            worker = threading.Thread(target=self._worker)
            workers.append(worker)
            worker.start()
        
        # 等待所有线程完成
        for worker in workers:
            worker.join()
        
        logger.info(f"Crawl finish，found page: {len(self.results)}")
        
        return self.results
    
    def _worker(self):
        """爬虫工作线程"""
        while True:
            try:
                # 获取URL和深度
                url, depth = self.url_queue.get(block=False)
                
                # 处理URL
                self._process_url(url, depth)
                
                # 标记任务完成
                self.url_queue.task_done()
            except queue.Empty:
                # 队列为空，检查是否所有线程都空闲
                with self.lock:
                    if self.url_queue.empty():
                        break
            except Exception as e:
                logger.error(e, origin="crawler")
    
    def _process_url(self, url, depth):
        """
        处理URL
        
        Args:
            url: 要处理的URL
            depth: 当前深度
        """
        # 如果超过最大深度，则跳过
        if depth > self.max_depth:
            return
            
        # 如果URL已访问，则跳过
        if url in self.visited_urls:
            return
            
        # 添加到已访问集合
        with self.lock:
            self.visited_urls.add(url)
        
        # 检查URL是否符合过滤条件
        if not self._should_crawl(url):
            return
            
        logger.debug(f"Crawl on page: {url}")
        
        # 发送HTTP请求
        response = requests.get(url)
        if not response or response.status_code != 200:
            logger.debug(f"Page Error: {url}, Status code: {response.status_code if response else 'None'}")
            return
            
        # 解析页面内容
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' not in content_type:
            logger.debug(f"Skip notHTML page: {url}, Content-Type: {content_type}")
            return
            
        # 解析HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 提取页面信息
        page_info = self._extract_page_info(url, soup, response)
        
        # 添加到结果
        with self.lock:
            self.results.append(page_info)
        
        # 如果未达到最大深度，则提取链接
        if depth < self.max_depth:
            links = self._extract_links(url, soup)
            for link in links:
                # 添加到队列
                self.url_queue.put((link, depth + 1))
    
    def _extract_page_info(self, url, soup, response):
        """
        提取页面信息
        
        Args:
            url: 页面URL
            soup: BeautifulSoup对象
            response: 响应对象
            
        Returns:
            dict: 页面信息
        """
        # 提取页面标题
        title = soup.title.string if soup.title else "No Title"
        
        # 提取表单
        forms = self._extract_forms(url, soup)
        
        # 提取URL参数
        params = self._extract_params(url)
        
        # 提取JavaScript事件
        events = self._extract_js_events(soup)
        
        # 提取HTTP头
        headers = dict(response.headers)
        
        return {
            'url': url,
            'title': title,
            'forms': forms,
            'params': params,
            'events': events,
            'headers': headers,
            'status_code': response.status_code,
            'content_length': len(response.content),
            'cookies': dict(response.cookies)
        }
    
    def _extract_links(self, base_url, soup):
        """
        提取页面中的链接
        
        Args:
            base_url: 基础URL
            soup: BeautifulSoup对象
            
        Returns:
            list: 提取的链接列表
        """
        links = []
        
        # 提取<a>标签链接
        for a in soup.find_all('a', href=True):
            link = a['href'].strip()
            if link:
                full_url = urljoin(base_url, link)
                links.append(full_url)
        
        # 提取<form>标签链接
        for form in soup.find_all('form', action=True):
            link = form['action'].strip()
            if link:
                full_url = urljoin(base_url, link)
                links.append(full_url)
        
        # 过滤链接
        filtered_links = []
        for link in links:
            # 跳过锚点链接
            if '#' in link:
                link = link.split('#')[0]
                if not link:
                    continue
            
            # 跳过JavaScript链接
            if link.startswith('javascript:'):
                continue
                
            # 跳过邮件链接
            if link.startswith('mailto:'):
                continue
                
            # 跳过电话链接
            if link.startswith('tel:'):
                continue
                
            # 跳过静态资源文件
            parsed_link = urlparse(link)
            path = parsed_link.path.lower()
            if any(path.endswith(ext) for ext in self.static_extensions):
                continue
                
            # 只爬取同一域名
            if parsed_link.netloc and parsed_link.netloc != self.base_domain:
                continue
                
            filtered_links.append(link)
        
        return list(set(filtered_links))
    
    def _extract_forms(self, base_url, soup):
        """
        提取页面中的表单
        
        Args:
            base_url: 基础URL
            soup: BeautifulSoup对象
            
        Returns:
            list: 表单列表
        """
        forms = []
        
        for form in soup.find_all('form'):
            form_info = {
                'id': form.get('id', ''),
                'name': form.get('name', ''),
                'method': form.get('method', 'get').upper(),
                'action': urljoin(base_url, form.get('action', '')),
                'fields': []
            }
            
            # 提取表单字段
            for field in form.find_all(['input', 'textarea', 'select']):
                # 跳过隐藏字段
                if field.name == 'input' and field.get('type') == 'hidden':
                    continue
                    
                field_info = {
                    'name': field.get('name', ''),
                    'id': field.get('id', ''),
                    'type': field.get('type', 'text') if field.name == 'input' else field.name,
                    'value': field.get('value', '')
                }
                
                form_info['fields'].append(field_info)
                
            forms.append(form_info)
            
        return forms
    
    def _extract_params(self, url):
        """
        提取URL参数
        
        Args:
            url: URL
            
        Returns:
            list: 参数列表
        """
        parsed_url = urlparse(url)
        params = [p[0] for p in parse_qsl(parsed_url.query)]
        return params
    
    def _extract_js_events(self, soup):
        """
        提取JavaScript事件
        
        Args:
            soup: BeautifulSoup对象
            
        Returns:
            list: 事件列表
        """
        events = []
        
        # 常见的JavaScript事件属性
        js_events = [
            'onclick', 'onmouseover', 'onmouseout', 'onload', 'onerror', 'onsubmit',
            'onchange', 'onkeyup', 'onkeydown', 'onkeypress', 'onblur', 'onfocus',
            'onreset', 'onselect', 'onabort', 'ondblclick', 'onmousedown', 'onmouseup',
            'onmousemove', 'onunload'
        ]
        
        # 查找所有带有JavaScript事件的标签
        for tag in soup.find_all():
            for event in js_events:
                if tag.has_attr(event):
                    events.append({
                        'tag': tag.name,
                        'event': event,
                        'code': tag[event]
                    })
                    
        return events
    
    def _should_crawl(self, url):
        """
        检查URL是否应该爬取
        
        Args:
            url: URL
            
        Returns:
            bool: 是否应该爬取
        """
        # 检查是否是HTTP或HTTPS协议
        if not url.startswith(('http://', 'https://')):
            return False
            
        # 检查排除模式
        if self.exclude_pattern and re.search(self.exclude_pattern, url):
            return False
            
        # 检查包含模式
        if self.include_pattern and not re.search(self.include_pattern, url):
            return False
            
        # 检查是否是静态资源文件
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        if any(path.endswith(ext) for ext in self.static_extensions):
            return False
            
        return True 