# modules/fetcher.py

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from bs4 import BeautifulSoup
import json
import time

class ProxyFetcher:
    """获取在线代理源."""
    def __init__(self):
        """初始化, 定义API和爬虫源."""
        # API源 (主要为返回纯文本格式的URL)
        self.online_sources = {
            'http': [
                # 经典源
                'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http',
                'https://openproxylist.xyz/http.txt',
                'https://www.proxy-list.download/api/v1/get?type=http',
                'https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http',
                'https://www.proxyscan.io/api/proxy?type=http&format=txt',
                # 您提供的新源
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                'http://77.93.157.21:3030/fetch_all',
                'http://199.245.100.84:5000/fetch_all',
                'http://123.117.160.38:5000/fetch_all',
                'http://142.171.31.40:5010/fetch_all',
                'http://120.46.21.7:5000/fetch_all',
            ],
            'https': [
                 'https://www.proxy-list.download/api/v1/get?type=https',
            ],
            'socks4': [
                'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4',
                'https://openproxylist.xyz/socks4.txt',
                'https://www.proxy-list.download/api/v1/get?type=socks4',
            ],
            'socks5': [
                'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5',
                'https://openproxylist.xyz/socks5.txt',
                'https://www.proxy-list.download/api/v1/get?type=socks5',
                'https://www.proxyscan.io/api/proxy?type=socks5&format=txt',
            ]
        }
        
        # 爬虫源 (需要解析HTML页面的网站)
        self.scraping_sources = [
            {'func': self._scrape_free_proxy_list, 'protocol': 'http'},
            {'func': self._scrape_kxdaili, 'protocol': 'http'},
            {'func': self._scrape_66ip, 'protocol': 'http'},
            {'func': self._scrape_fatezero, 'protocol': 'http'},
            # 新增的国内代理源
            {'func': self._scrape_kuaidaili, 'protocol': 'http'},
            {'func': self._scrape_ip3366, 'protocol': 'http'},
            {'func': self._scrape_89ip, 'protocol': 'http'},
        ]

        self.session = self._create_robust_session()

    def _create_robust_session(self):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Referer": "https://www.google.com/"
        })
        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session
        
    def _parse_proxies_from_text(self, text: str):
        try:
            data = json.loads(text)
            if 'data' in data and isinstance(data['data'], list):
                return [f"{item['ip']}:{item['port']}" for item in data['data']]
        except json.JSONDecodeError:
            pass
        
        return [line.strip() for line in text.splitlines() if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', line.strip())]

    def _fetch_from_url(self, url: str, log_queue):
        display_url = url.split('/')[2]
        log_queue.put(f"[*] (API) 正在从 {display_url} 获取...")
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            proxies = self._parse_proxies_from_text(response.text)
            if proxies:
                log_queue.put(f"[+] (API) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
                return proxies
            else:
                log_queue.put(f"[-] (API) 从 {display_url} 获取为空。")
                return None
        except requests.RequestException as e:
            log_queue.put(f"[!] (API) 从 {display_url} 获取失败: {e}")
            return None
            
    def _scrape_free_proxy_list(self, log_queue):
        url = 'https://free-proxy-list.net/'
        display_url = url.split('/')[2]
        log_queue.put(f"[*] (Scrape) 正在从 {display_url} 获取...")
        try:
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.content, 'lxml')
            proxies = set()
            table = soup.find('table', class_='table-striped')
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) > 6 and cols[6].text.strip() == 'yes':
                    ip = cols[0].text.strip()
                    port = cols[1].text.strip()
                    proxies.add(f"{ip}:{port}")
            log_queue.put(f"[+] (Scrape) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
            return list(proxies)
        except Exception as e:
            log_queue.put(f"[!] (Scrape) 从 {display_url} 获取失败: {e}")
            return None

    def _scrape_kxdaili(self, log_queue):
        url = 'http://www.kxdaili.com/dailiip/1/1.html'
        display_url = url.split('/')[2]
        log_queue.put(f"[*] (Scrape) 正在从 {display_url} 获取...")
        try:
            response = self.session.get(url, timeout=15)
            response.encoding = 'gb2312'
            soup = BeautifulSoup(response.content, 'lxml')
            proxies = set()
            table = soup.find('table', class_='active')
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) > 3 and 'HTTPS' in cols[3].text.upper():
                    ip = cols[0].text.strip()
                    port = cols[1].text.strip()
                    proxies.add(f"{ip}:{port}")
            log_queue.put(f"[+] (Scrape) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
            return list(proxies)
        except Exception as e:
            log_queue.put(f"[!] (Scrape) 从 {display_url} 获取失败: {e}")
            return None
            
    def _scrape_66ip(self, log_queue):
        url = "http://www.66ip.cn/nmtq.php?get_num=300&isp=0&anonym=0&type=2"
        display_url = url.split('/')[2]
        log_queue.put(f"[*] (API) 正在从 {display_url} 获取...")
        try:
            response = self.session.get(url, timeout=15)
            response.encoding = response.apparent_encoding
            proxies = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}', response.text)
            if proxies:
                log_queue.put(f"[+] (API) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
                return proxies
            else:
                log_queue.put(f"[-] (API) 从 {display_url} 获取为空。")
                return None
        except Exception as e:
            log_queue.put(f"[!] (API) 从 {display_url} 获取失败: {e}")
            return None

    def _scrape_fatezero(self, log_queue):
        url = "http://proxylist.fatezero.org/proxy.list"
        display_url = url.split('/')[2]
        log_queue.put(f"[*] (Scrape) 正在从 {display_url} 获取...")
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            proxies = set()
            for line in response.text.split('\n'):
                if 'host' in line:
                    proxy_info = json.loads(line)
                    if proxy_info.get('type') in ('http', 'https'):
                         host = proxy_info.get('host')
                         port = proxy_info.get('port')
                         proxies.add(f"{host}:{port}")

            if proxies:
                log_queue.put(f"[+] (Scrape) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
                return list(proxies)
            else:
                 log_queue.put(f"[-] (Scrape) 从 {display_url} 获取为空。")
                 return None
        except Exception as e:
            log_queue.put(f"[!] (Scrape) 从 {display_url} 获取失败: {e}")
            return None

    # --- 新增国内代理源爬虫 ---
    def _scrape_kuaidaili(self, log_queue):
        """爬取快代理网站的国内高匿代理。"""
        proxies = set()
        display_url = "kuaidaili.com"
        log_queue.put(f"[*] (Scrape) 正在从 {display_url} 获取...")
        try:
            for page in range(1, 4):  # 爬取前3页
                url = f"https://www.kuaidaili.com/free/inha/{page}/"
                response = self.session.get(url, timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'lxml')
                table = soup.find('table')
                if not table: continue
                for row in table.find('tbody').find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) > 1:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        proxies.add(f"{ip}:{port}")
                time.sleep(1) # 友好爬取，避免被封
            
            if proxies:
                log_queue.put(f"[+] (Scrape) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
                return list(proxies)
            return None
        except Exception as e:
            log_queue.put(f"[!] (Scrape) 从 {display_url} 获取失败: {e}")
            return None

    def _scrape_ip3366(self, log_queue):
        """爬取云代理(ip3366.net)的国内高匿代理。"""
        proxies = set()
        display_url = "ip3366.net"
        log_queue.put(f"[*] (Scrape) 正在从 {display_url} 获取...")
        try:
            for page in range(1, 4): # 爬取前3页
                url = f"http://www.ip3366.net/free/?stype=1&page={page}"
                response = self.session.get(url, timeout=15)
                response.encoding = 'gb2312'
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'lxml')
                table = soup.find('table', id='list')
                if not table: continue
                for row in table.find('tbody').find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) > 1:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        proxies.add(f"{ip}:{port}")
                time.sleep(1)
            
            if proxies:
                log_queue.put(f"[+] (Scrape) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
                return list(proxies)
            return None
        except Exception as e:
            log_queue.put(f"[!] (Scrape) 从 {display_url} 获取失败: {e}")
            return None

    def _scrape_89ip(self, log_queue):
        """爬取89免费代理(89ip.cn)的代理。"""
        proxies = set()
        display_url = "89ip.cn"
        log_queue.put(f"[*] (Scrape) 正在从 {display_url} 获取...")
        try:
            for page in range(1, 4): # 爬取前3页
                url = f"https://www.89ip.cn/index_{page}.html"
                response = self.session.get(url, timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'lxml')
                table = soup.find('table', class_='layui-table')
                if not table: continue
                for row in table.find('tbody').find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) > 1:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        proxies.add(f"{ip}:{port}")
                time.sleep(1)
            
            if proxies:
                log_queue.put(f"[+] (Scrape) 成功从 {display_url} 获取 {len(proxies)} 个代理。")
                return list(proxies)
            return None
        except Exception as e:
            log_queue.put(f"[!] (Scrape) 从 {display_url} 获取失败: {e}")
            return None

    def fetch_all(self, log_queue, cancel_event=None):
        all_proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
        
        executor = ThreadPoolExecutor(max_workers=50)
        try:
            future_to_protocol = {}

            # 提交API源任务
            for protocol, urls in self.online_sources.items():
                for url in urls:
                    if cancel_event and cancel_event.is_set(): break
                    future = executor.submit(self._fetch_from_url, url, log_queue)
                    future_to_protocol[future] = protocol
                if cancel_event and cancel_event.is_set(): break
            
            # 提交爬虫源任务
            if not (cancel_event and cancel_event.is_set()):
                for source in self.scraping_sources:
                    if cancel_event and cancel_event.is_set(): break
                    future = executor.submit(source['func'], log_queue)
                    future_to_protocol[future] = source['protocol']

            # 处理已完成的future
            for future in as_completed(future_to_protocol):
                if cancel_event and cancel_event.is_set():
                    break
                protocol = future_to_protocol[future]
                try:
                    proxies = future.result()
                    if proxies:
                        if protocol == 'https':
                            all_proxies['http'].update(proxies)
                        else:
                            all_proxies[protocol].update(proxies)
                except Exception as exc:
                    log_queue.put(f'[!] 获取器线程产生一个错误: {exc}')
        finally:
            executor.shutdown(wait=not (cancel_event and cancel_event.is_set()))

        if 'https' in all_proxies:
            del all_proxies['https']
            
        return {
            'http': list(all_proxies.get('http', set())),
            'socks4': list(all_proxies.get('socks4', set())),
            'socks5': list(all_proxies.get('socks5', set()))
        }