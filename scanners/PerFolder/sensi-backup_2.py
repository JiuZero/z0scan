#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/12
# JiuZero 2025/3/4
# Refer: https://www.t00ls.net/viewthread.php?tid=47698&highlight=%E5%A4%87%E4%BB%BD
# Refer: https://www.t00ls.net/viewthread.php?tid=45430&highlight=%E5%A4%87%E4%BB%BD

import os
import requests

from api import conf, generateResponse, VulType, KB, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "sensi-backup_2"
    desc = 'Backup File Of Each Folder (Directory-based)'
    version = "2025.3.4"
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
        
    def audit(self):
        if self.requests.url.count("/") > int(conf.max_dir) + 2:
            return
        if self.risk in conf.risk and conf.level != 0 and not self.name in KB.disable:
            file_dic = conf.lists["backup"]
            url = self.requests.url.rstrip("/")
            directory = os.path.basename(url)
            headers = self.requests.headers.copy()

            for payload in file_dic:
                test_url = url + "/" + payload
                try:
                    r = requests.get(test_url, headers=headers, allow_redirects=False, stream=True)
                except requests.exceptions.MissingSchema:
                    continue
                content = r.raw.read(10)
                if r.status_code == 200 and self._check(content):
                    if int(r.headers.get('Content-Length', 0)) == 0:
                        continue

                    rarsize = int(r.headers.get('Content-Length')) // 1024 // 1024
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": r.url, 
                        "vultype": VulType.SENSITIVE, 
                        "show": {
                            "Sizes {}M".format(rarsize)
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": content.decode(errors='ignore'), 
                        "desc": "File Sizes {}M".format(rarsize)
                        })
                    self.success(result)
