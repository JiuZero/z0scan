import requests
import base64
from lib.core.log import logger
from lib.core.data import conf
from concurrent.futures import ThreadPoolExecutor, as_completed

class AssetSearcher:
    """通过网络空间搜索引擎 (Fofa, Quake, Hunter) 获取SOCKS5代理。"""
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        })

    def _search_fofa(self, key, query, size):
        """从Fofa搜索代理"""
        logger.info(f"[*] (Fofa) 开始搜索, 数量: {size}, 语法: {query}", origin="AssetSearcher")
        if not key:
            logger.error("[!] (Fofa) 失败: 未提供API Key。", origin="AssetSearcher")
            return []
        # Fofa API 需要email和key，这里简化处理，假设用户在key字段填入`email:key`或仅`key`
        email = ''
        if ':' in key:
            try:
                email, key = key.split(':', 1)
            except ValueError:
                logger.error("[!] (Fofa) 失败: Key格式不正确，应为 `email:key`。")
                return []
        if not key:
            logger.error("[!] (Fofa) 失败: 未提供API Key。")
            return []
        proxies = []
        try:
            qbase64 = base64.b64encode(query.encode()).decode()
            # 注意: Fofa免费账户的API可能不支持搜索所有字段，且返回数量有限
            api_url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={qbase64}&size={size}&fields=host,ip,port"
            response = self.session.get(api_url, timeout=20)
            response.raise_for_status()
            data = response.json()
            if data.get("error"):
                logger.info(f"[!] (Fofa) API返回错误: {data.get('errmsg')}")
                return []
            results = data.get("results", [])
            for res in results:
                # res 是一个列表 [host, ip, port]
                if len(res) >= 3 and res[2] is not None:
                     proxies.append(f"{res[1]}:{res[2]}")
            logger.info(f"[+] (Fofa) 成功获取 {len(proxies)} 个潜在代理。")
            return proxies
        except requests.RequestException as e:
            logger.info(f"[!] (Fofa) 请求失败: {e}")
        except Exception as e:
            logger.info(f"[!] (Fofa) 处理时发生未知错误: {e}")
        return []

    def _search_quake(self, key, query, size):
        """从Quake搜索代理"""
        logger.info(f"[*] (Quake) 开始搜索, 数量: {size}, 语法: {query}")
        if not key:
            logger.info("[!] (Quake) 失败: 未提供API Key。")
            return []
        proxies = []
        try:
            api_url = "https://quake.360.cn/api/v3/search/quake_service"
            headers = {'X-QuakeToken': key, 'Content-Type': 'application/json'}
            post_data = {"query": query, "start": 0, "size": size}
            response = self.session.post(api_url, headers=headers, json=post_data, timeout=20)
            response.raise_for_status()
            data = response.json()
            if data.get("code") != 0:
                # [MODIFIED] 增加更详细的错误日志
                logger.info(f"[!] (Quake) API返回错误: {data.get('message')} | 响应: {response.text}")
                return []
            results = data.get("data", [])
            for res in results:
                ip = res.get("ip")
                port = res.get("port")
                if ip and port:
                    proxies.append(f"{ip}:{port}")
            logger.info(f"[+] (Quake) 成功获取 {len(proxies)} 个潜在代理。")
            return proxies
        except requests.RequestException as e:
            logger.info(f"[!] (Quake) 请求失败: {e}")
        except Exception as e:
            logger.info(f"[!] (Quake) 处理时发生未知错误: {e}")
        return []
        
    def _search_hunter(self, key, query, size):
        """从Hunter搜索代理"""
        logger.info(f"[*] (Hunter) 开始搜索, 数量: {size}, 语法: {query}")
        if not key:
            logger.info("[!] (Hunter) 失败: 未提供API Key。")
            return [] 
        proxies = []
        try:
            # Hunter API 需要对查询语法进行base64编码
            search_b64 = base64.b64encode(query.encode()).decode()
            # Hunter每页最多100条
            page_size = min(size, 100)
            api_url = f"https://hunter.qianxin.com/openApi/search?api-key={key}&search={search_b64}&page=1&page_size={page_size}"
            response = self.session.get(api_url, timeout=20)
            response.raise_for_status()
            data = response.json()
            if data.get("code") != 200:
                logger.info(f"[!] (Hunter) API返回错误: {data.get('message')}")
                return []
            results = data.get("data", {}).get("arr", [])
            for res in results:
                ip = res.get("ip")
                port = res.get("port")
                if ip and port:
                    proxies.append(f"{ip}:{port}")
            logger.info(f"[+] (Hunter) 成功获取 {len(proxies)} 个潜在代理。")
            return proxies
        except requests.RequestException as e:
            logger.info(f"[!] (Hunter) 请求失败: {e}")
        except Exception as e:
            logger.info(f"[!] (Hunter) 处理时发生未知错误: {e}")
        return []

    def search_all(self, fetch_settings):
        """并发执行所有启用的搜索引擎任务"""
        all_proxies = set()
        executor = ThreadPoolExecutor(max_workers=3)
        futures = []
        cfg = conf.autoproxy.get("fofa", {})
        if cfg.get('enabled'):
            futures.append(executor.submit(self._search_fofa, cfg.get('key'), cfg.get('query'), cfg.get('size')))
        cfg = conf.get("quake").get('quake', {})
        if cfg.get('enabled'):
            futures.append(executor.submit(self._search_quake, cfg.get('key'), cfg.get('query'), cfg.get('size')))
        cfg = conf.get("hunter").get('hunter', {})
        if cfg.get('enabled'):
            futures.append(executor.submit(self._search_hunter, cfg.get('key'), cfg.get('query'), cfg.get('size')))
        try:
            for future in as_completed(futures):
                try:
                    proxies = future.result()
                    if proxies:
                        all_proxies.update(proxies)
                except Exception as e:
                    logger.info(f"[!] 搜索线程出现异常: {e}")
        finally:
            executor.shutdown(wait=False)
        return list(all_proxies)