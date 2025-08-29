import sys, json, re, os
from lib.core.log import logger
from lib.core.data import conf
from lib.helper.autoproxy.fetcher import ProxyFetcher
from lib.helper.autoproxy.checker import ProxyChecker
from lib.helper.autoproxy.searcher import AssetSearcher

class AutoProxy():
    def __init__(self):
        self.fetcher = ProxyFetcher()
        self.asset_searcher = AssetSearcher()
        self.checker = ProxyChecker()
        
    def import_proxies(self, file_path: str):
        # 从文件中导入代理并返回字典
        proxies_by_protocol = {'http': [], 'socks4': [], 'socks5': []}
        valid_parse_protocols = {'http', 'https', 'socks4', 'socks5'}
        try:
            _, ext = os.path.splitext(file_path)
            if ext.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            url, protocol = item.get('url'), item.get('protocol', 'http').lower()
                            if url:
                                parsed = re.match(r'(\w+)://(.+)', url)
                                if parsed: protocol, proxy = parsed.groups()
                                else: proxy = url
                            else: proxy = f"{item.get('ip')}:{item.get('port')}"
                            if protocol == 'https': protocol = 'http'
                            if protocol in proxies_by_protocol: proxies_by_protocol[protocol].append(proxy)
            else: 
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'): continue
                        protocol, proxy_address = 'http', line
                        match = re.match(r'(\w+)://(.+)', line)
                        if match:
                            proto_part, proxy_part = match.groups()
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
            logger.error("Error: {e}")
            sys.exit(0)
    
    def fetch_proxies(self, mode=1):
        # 获取代理
        if mode == 1:
            # 公用免费代理
            logger.info("Start to fetch for free proxies...", origin="AutoProxy")
            proxies_by_protocol = self.fetcher.fetch_all()
            return proxies_by_protocol
        elif mode == 2:
            # 空间搜索引擎爬取
            logger.info("Start to crawl for proxies...", origin="AutoProxy")
            proxies_by_protocol = {'socks5': set()}
            asset_proxies = self.asset_searcher.search_all()
            if asset_proxies:
                proxies_by_protocol['socks5'].update(asset_proxies)
            else:
                logger.error("No result return...exit", origin="AutoProxy")
                sys.exit(0)
            proxies_to_validate = {proto: list(proxy_set) for proto, proxy_set in proxies_by_protocol.items()}
            return proxies_by_protocol

    def validation_proxies(self, proxies_by_protocol, validation_mode='online'):
        # 验证代理有效性
        # total_to_validate = sum(len(v) for v in proxies_by_protocol.values())
        proxies_by_protocol = self.checker.validate_all(
            proxies_by_protocol, validation_mode, max_workers=conf.autoproxy["threads"],
        )
        return proxies_by_protocol
        
    def export_proxies(self, file_path: str, proxies_by_protocol: dict):
        # 导出代理
        try:
            _, ext = os.path.splitext(file_path)
            if ext.lower() == '.json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    export_data = [{'protocol': p['protocol'], 'proxy': p['proxy'], 'location': p['location']} for p in proxies_by_protocol]
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                """
            elif ext.lower() == '.csv':
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    f.write("score,anonymity,protocol,proxy,latency_ms,speed_mbps,location\n")
                    for p in proxies_by_protocol:
                        lat_ms, spd_mbps = f"{p['latency'] * 1000:.1f}", f"{p['speed']:.2f}"
                        score = p.get('score', 0)
                        f.write(f"{score:.1f},{p['anonymity']},{p['protocol']},{p['proxy']},{lat_ms},{spd_mbps},\"{p['location']}\"\n")
                """
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for p in proxies_by_protocol: f.write(f"{p['protocol'].lower()}://{p['proxy']}\n")
            logger.info(f"Success export {len(proxies_by_protocol)} proxies to {file_path}.", origin="AutoProxy")
        except Exception as e:
            logger.error("Error: {e}", origin="AutoProxy")
            sys.exit(0)

