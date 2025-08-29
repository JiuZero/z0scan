# modules/checker.py

import requests
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

class ProxyChecker:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        })
        
        self.validation_targets = {
            'latency_check': 'https://www.baidu.com',
        }
        self.public_ip = None

    def _full_check_proxy(self, proxy_info: dict):
        proxy = proxy_info['proxy']
        protocol = proxy_info['protocol']
        proxy_url = f"{protocol.lower()}://{proxy}"
        proxies_dict = {'http': proxy_url, 'https': proxy_url}
        result = {
            'proxy': proxy, 
            'protocol': protocol.upper(), 
            'latency': float('inf'), 
        }
        try:
            if not self._pre_check_proxy(proxy):
                return None
            start_time = time.time()
            self.session.head(self.validation_targets['latency_check'], proxies=proxies_dict, timeout=self.timeout).raise_for_status()
            result['latency'] = time.time() - start_time
            return result
        except requests.RequestException:
            return None
        except Exception:
            return None

    def _pre_check_proxy(self, proxy: str):
        """TCP预检，快速判断端口是否开放。"""
        try:
            ip, port_str = proxy.split(':')
            with socket.create_connection((ip, int(port_str)), timeout=1.5):
                return True
        except Exception:
            return False
            
    def validate_all(self, proxies_by_protocol: dict, max_workers=8):
        all_proxies_flat = [{'proxy': p, 'protocol': proto} for proto, proxies in proxies_by_protocol.items() for p in proxies]
        executor = ThreadPoolExecutor(max_workers=max_workers)
        futures = [executor.submit(self._full_check_proxy) for p in all_proxies_flat]
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    proxies_queue.put(result)
            except Exception as e:
                logger.error(f"[!] 验证器线程出现异常: {e}")