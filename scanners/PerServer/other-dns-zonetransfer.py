#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/11

import dns.resolver
import dns.zone
import dns.exception
from lib.core.common import is_ipaddr
from api import generateResponse, VulType, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = "other-dns-zonetransfer"
    desc = 'DNS Zone Transfer Vulnerability'
    version = "2025.5.11"
    risk = 1
    
    def audit(self):
        if not conf.level == 0 and is_ipaddr(self.requests.hostname) and self.risk in conf.risk or self.name in KB.disable:
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
            ans = dns.resolver.query(fqdn, 'NS')
            return [a.to_text() for a in ans]
        except dns.exception.DNSException:
            return []

    def axfr(self, domain, ns):
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=conf.timeout))
            return [z[n].to_text(n) for n in z.nodes.keys()]
        except:
            return None

    def check_dns_zone_transfer(self, domain):
        # domain = "sxau.edu.cn"
        nservers = [n for n in self.nameservers(domain)]
        result = []
        for ns in nservers:
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
