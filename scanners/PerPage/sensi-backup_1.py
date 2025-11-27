#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/5/15

import os
import requests
from urllib.parse import urlparse

from api import generateResponse, VulType, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = 'sensi-backup_1'
    desc = 'Backup File Detection (File-based)'
    version = "2025.5.15"
    risk = 1
        
    def _check(self, content):
        """
            根据给定的url，探测远程服务器上是存在该文件
            文件头识别
           * rar:526172211a0700cf9073
           * zip:504b0304140000000800
           * gz：1f8b080000000000000b，也包括'.sql.gz'，取'1f8b0800' 作为keyword
           * tar.gz: 1f8b0800
           * mysqldump:                   -- MySQL dump:               2d2d204d7953514c
           * phpMyAdmin:                  -- phpMyAdmin SQL Dump:      2d2d207068704d794164
           * navicat:                     /* Navicat :                 2f2a0a204e617669636174
           * Adminer:                     -- Adminer x.x.x MySQL dump: 2d2d2041646d696e6572
           * Navicat MySQL Data Transfer: /* Navicat:                  2f2a0a4e617669636174
           * 一种未知导出方式:               -- -------:                  2d2d202d2d2d2d2d2d2d
            :param target_url:
            :return:
        """
        features = [b'\x50\x4b\x03\x04', b'\x52\x61\x72\x21',
                    b'\x2d\x2d\x20\x4d', b'\x2d\x2d\x20\x70\x68', b'\x2f\x2a\x0a\x20\x4e',
                    b'\x2d\x2d\x20\x41\x64', b'\x2d\x2d\x20\x2d\x2d', b'\x2f\x2a\x0a\x4e\x61']
        for i in features:
            if content.startswith(i):
                return True
        return False

    def _is_valid_payload(self, url):
        """检查payload是否有效，避免修改域名部分"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname and any(hostname.endswith(ext) for ext in ['.bak', '.rar', '.zip']):
                return False
            return True
        except:
            return False

    def audit(self):
        if conf.level == 0:
            return
        headers = self.requests.headers
        url = self.requests.url

        parsed_url = urlparse(url)
        if not parsed_url.path:  # 如果没有路径，直接返回
            return

        # 分离路径和扩展名
        path = parsed_url.path
        dirname, filename = os.path.split(path)
        name, ext = os.path.splitext(filename)

        payloads = []
        if name:  # 确保文件名不为空
            payloads.append(f"{parsed_url.scheme}://{parsed_url.netloc}{dirname}/{name}.bak")
            payloads.append(f"{parsed_url.scheme}://{parsed_url.netloc}{dirname}/{name}.rar")
            payloads.append(f"{parsed_url.scheme}://{parsed_url.netloc}{dirname}/{name}.zip")
        
        # 基于完整URL的payload
        payloads.append(url + ".bak")
        payloads.append(url + ".rar")
        payloads.append(url + ".zip")

        valid_payloads = [p for p in payloads if self._is_valid_payload(p)]
        
        if not valid_payloads:
            return

        # http://xxxxx.com/index.php => index.php.bak index.bak index.rar
        for payload in valid_payloads:
            r = requests.get(payload, headers=headers, allow_redirects=False, timeout=10)
            if r.status_code == 200:
                try:
                    content = r.raw.read(10)
                except:
                    continue
                if self._check(content) or "application/octet-stream" in r.headers.get("Content-Type", ''):
                    rarsize = int(r.headers.get('Content-Length', 0)) // 1024 // 1024
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.BRUTE_FORCE
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": content.decode(errors='ignores'), 
                        "desc": "Sizes: {}M".format(rarsize)
                        })
                    self.success(result)