#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/7

from api import generateResponse, VulType, Type, PluginBase, conf, logger
import os
import re, requests
from urllib import parse
from urllib.parse import urlparse

class Z0SCAN(PluginBase):
    name = "sensi-sourcecode"
    desc = "Source Code Disclosure Detection"
    version = "2025.6.7"
    risk = 1

    def audit(self):
        if not 1 in conf.risk or conf.level == 0:
            return
        accepted_ext = ["php", "php3", "php4", "php5", "asp", "aspx", "jsp", "cfm", "pl", "shtml"]
        if not self.requests.suffix.lower().lstrip('.') in accepted_ext:
            return
        parsed = urlparse(self.requests.url)
        dirname = os.path.dirname(parsed.path)
        basename = os.path.basename(parsed.path)
        filename, ext = os.path.splitext(basename)
        test_paths = [
            filename + "/%3f." + ext,
            filename + ext.upper(),
            filename + ext[:-1] + parse.quote(ext[-1]),
            filename + "%252e" + ext,
            basename + ".%E2%73%70",
            basename + "%2easp",
            basename + "%2e",
            basename + "\\",
            basename + "?*",
            basename + "+",
            basename + "%20",
            basename + "%00",
            basename + "%01",
            basename + "%2f",
            basename + "%5c",
            basename + ".htr",
            basename + "::DATA"
        ]
        code_patterns = [
            br"(\<%[\s\S]*Response\.Write[\s\S]*%\>)",  # ASP
            br"(\<\?php[\x20-\x80\x0d\x0a\x09]+)",      # PHP
            br"(^#\!\\\/[\s\S]*\\\/perl)",              # Perl
            br"(^#\!\/[\s\S]*?\/python)",               # Python
            br"(^#\!\/usr\/bin\/env\spython)",          # Python
            br"(^#\!\/[\s\S]*?\/perl)",                 # Perl
            br"using\sSystem[\s\S]*?class\s[\s\S]*?\s?{[\s\S]*}"  # .NET
        ]
        for path in test_paths:
            full_path = os.path.join(dirname, path)
            full_url = f"{self.requests.netloc}{full_path}"
            r = requests.get(full_url, headers=self.requests.headers, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            content = r.content[:1000]  # 只检查前1000字节
            for pattern in code_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self._report_vulnerability(r, full_url, pattern)
                    return
                
    def _report_vulnerability(self, response, vul_url, pattern):
        result = self.generate_result()
        result.main({
            "type": Type.REQUEST,
            "url": vul_url,
            "vultype": VulType.SENSITIVE,
            "show": {
                "Pattern": pattern.decode(),
            }
        })
        result.step("Detection", {
            "request": getattr(response.request, 'reqinfo', ''),
            "response": generateResponse(response),
            "desc": f"Found source code pattern: {pattern.decode()}"
        })
        self.success(result)