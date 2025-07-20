#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/7
from api import generateResponse, VulType, Type, PluginBase, conf, logger, random_str, KB
import os
import difflib, requests
from urllib.parse import urlparse

class Z0SCAN(PluginBase):
    name = "sensi-editfileleak"
    desc = "Editor Backup File Leak Detection"
    version = "2025.6.7"
    risk = 1
    SIMILARITY_THRESHOLD = 0.8

    def audit(self):
        if self.requests.suffix.lower() not in {".php", ".jsp", ".asp", ".aspx", ".html", ".htm", ".py", ".rb"}:
            return
        if not self.risk in conf.risk or conf.level == 0 or self.name in KB.disable:
            return
        parsed = urlparse(self.requests.url)
        dirname, basename = os.path.dirname(parsed.path), os.path.basename(parsed.path)
        if not basename:  # 跳过目录请求
            return
        rand_str = random_str(6).lower()
        test_paths = [
            (f"{dirname}/.{basename}.swp", f"{dirname}/.{rand_str}{basename}.swp"),
            (f"{dirname}/{basename}~", f"{dirname}/{rand_str}{basename}~")
        ]
        for real_path, fake_path in test_paths:
            real_url = f"{self.requests.netloc}{real_path}"
            fake_url = f"{self.requests.netloc}{fake_path}"
            r_real = requests.get(real_url, headers=self.requests.headers, allow_redirects=False)
            if not (r_real and r_real.status_code == 200 and 
                   "text/html" not in r_real.headers.get("Content-Type", "").lower()):
                continue
            r_fake = requests.get(fake_url, headers=self.requests.headers, allow_redirects=False)
            if not r_fake:
                continue
            try:
                content_real = r_real.content.decode('utf-8', errors='ignore')
                content_fake = r_fake.content.decode('utf-8', errors='ignore')
                similarity = difflib.SequenceMatcher(None, content_real, content_fake).ratio()
            except Exception as e:
                # logger.warning(f"Similarity check failed: {e}", origin=self.name)
                continue
            if similarity < self.SIMILARITY_THRESHOLD:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST,
                    "url": real_url,
                    "vultype": VulType.SENSITIVE,
                    "show": {
                        "File": real_path,
                        "Msg": f"Similarity: {similarity:.2f} (threshold: {self.SIMILARITY_THRESHOLD})"
                    }
                })
                result.step("Detection", {
                    "request": getattr(r_real.request, 'reqinfo', ''),
                    "response": generateResponse(r_real),
                    "desc": f"Found backup file with low similarity to random file"
                })
                self.success(result)
                break