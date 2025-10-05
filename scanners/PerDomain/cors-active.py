#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Reference: https://github.com/chenjj/CORScanner
# JiuZero 2025/5/25

import inspect, tldextract
from urllib.parse import urlparse
from lib.helper.helper_cors import is_cors_permissive
from api import generateResponse, VulType, PLACE, Type, PluginBase, KB, conf

class Z0SCAN(PluginBase):
    name = "cors-active"
    desc = 'CORS Vulnerability (Active Detection)'
    version = "2025.5.25"
    risk = 2

    def cors_result(self, module, msg, desc):
        if msg:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST,
                "url": self.requests.protocol + "://" + self.requests.hostname + ":" + str(self.requests.port),
                "vultype": VulType.CORS,
                "show": {
                    "Module": module,
                    "Origin": msg.get("test_origin"),
                    "Credentials": msg.get("credentials"),
                }
            })
            result.step("Request1", {
                "request": msg.get("resp").reqinfo,
                "response": generateResponse(msg.get("resp")),
                "desc": module,
            })
            self.success(result)
        return
    
    def test_reflect_origin(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        test_origin = self.requests.protocol + "://" + "evil.com"
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_prefix_match(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        test_origin = self.requests.protocol + "://" + self.netloc_split_port + ".evil.com"
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")
            
    def test_suffix_match(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        sld = tldextract.extract(test_url.strip()).registered_domain
        test_origin = self.requests.protocol + "://" + "evil" + sld
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_trust_null(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        test_origin = "null"
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_include_match(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        sld = tldextract.extract(test_url.strip()).registered_domain
        test_origin = self.requests.protocol + "://" + sld[1:]
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_not_escape_dot(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        sld = tldextract.extract(test_url.strip()).registered_domain
        domain = self.netloc_split_port
        test_origin = self.requests.protocol + "://" + domain[::-1].replace('.', 'a', 1)[::-1]
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_trust_any_subdomain(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        test_origin = self.requests.protocol + "://" + "evil." + self.netloc_split_port
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_https_trust_http(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        if self.requests.protocol != "https":
            return
        test_origin = "http://" + self.netloc_split_port
        msg = self.is_cors_permissive(test_origin, test_url)
        self.cors_result(module_name, msg, "")

    def test_custom_third_parties(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        sld = tldextract.extract(test_url.strip()).registered_domain
        domain = self.netloc_split_port
        is_cors_perm = False
        for test_origin in conf.lists["origins"]:
            is_cors_perm = self.is_cors_permissive(test_origin, test_url)
            if is_cors_perm: break
        self.cors_result(module_name, is_cors_perm, "")
    
    def test_special_characters_bypass(self):
        module_name = inspect.stack()[0][3].replace('test_','')
        test_url = self.requests.url
        special_characters = ['_','-','"','{','}','+','^','%60','!','~','`',';','|','&',"'",'(',')','*',',','$','=','+',"%0b"]
        origins = []
        for char in special_characters:
            attempt = self.requests.protocol + "://" + self.netloc_split_port + char + ".evil.com"
            origins.append(attempt)
        is_cors_perm = False
        for test_origin in origins:
            is_cors_perm = self.is_cors_permissive(test_origin, test_url)
            if is_cors_perm: break
        self.cors_result(module_name, is_cors_perm, "")
    
    def audit(self):
        if not self.risk in conf.risk or conf.level == 0:
            return
        self.netloc_split_port = urlparse(self.requests.url).netloc.split(':')[0]
        functions = [
            'test_reflect_origin',
            'test_prefix_match',
            'test_suffix_match',
            'test_trust_null',
            'test_include_match',
            'test_not_escape_dot',
            'test_custom_third_parties',
            'test_special_characters_bypass',
            'test_trust_any_subdomain',
            'test_https_trust_http',
        ]
        for fname in functions:
            func = getattr(self,fname)
        return