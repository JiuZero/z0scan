#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/11

import dns.resolver
import dns.zone
import dns.exception
import re
from lib.core.common import is_ipaddr
from api import generateResponse, VulType, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = "other-dns-zonetransfer"
    desc = 'DNS Zone Transfer Vulnerability'
    version = "2025.5.11"
    risk = 1
    
    def audit(self):
        if not conf.level == 0 and not is_ipaddr(self.requests.hostname) and self.risk in conf.risk:
            domains = self.split_domain_and_check(self.requests.hostname)
            if domains:
                for domain in domains:
                    res, resdata = self.check_dns_zone_transfer(domain)
                    if res:
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": self.requests.hostname, 
                            "vultype": VulType.SENSITIVE
                            })
                        result.step("Request1", {
                            "request": self.requests.raw, 
                            "response": self.response.raw, 
                            "desc": ""
                            })
                        self.success(result)
                
    def nameservers(self, fqdn):
        try:
            ans = dns.resolver.resolve(fqdn, 'NS')
            return [a.to_text() for a in ans]
        except dns.exception.DNSException:
            return []

    def axfr(self, domain, ns):
        try:
            # 确保 ns 是有效的 DNS 服务器格式，若 ns 是域名，尝试解析为 IP
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ns):
                try:
                    ns_ip = dns.resolver.resolve(ns, 'A')[0].to_text()
                except:
                    return None
            else:
                ns_ip = ns
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=conf.timeout))
            return [z[n].to_text(n) for n in z.nodes.keys()]
        except:
            return None

    def check_dns_zone_transfer(self, domain):
        nservers = self.nameservers(domain)
        result = []
        for ns in nservers:
            # 过滤无效的 DNS 服务器格式
            if not ns:
                continue
            recs = self.axfr(domain, ns)
            if recs is not None:
                result.append(
                    {
                        "domain": domain,
                        "nameserver": ns,
                        "data": recs
                    }
                )
        if result:
            return True, result
        return False, result

    def split_domain_and_check(self, domain):
        domains = []
        for num in range(domain.count(".")):
            res = ".".join(domain.split(".")[-(num + 1):])
            domains.append(res)
        return domains