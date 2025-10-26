#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/11
# JiuZero 2025/6/5

import re

def get_phpinfo(html) -> list:
    rules = [
        (r'<td class="e">allow_url_fopen<\/td><td class="v">On<\/td>', 'allow_url_fopen: On (Allows using the fopen function to open URLs)'),
        (r'<td class="e">asp_tags<\/td><td class="v">On<\/td>', 'asp_tags: On (Enables ASP-style tag parsing)'),
        (r'<td class="e">register_globals<\/td><td class="v">On<\/td>', 'register_globals: On'),
        (r'<td class="e">enable_dl<\/td><td class="v">On<\/td>',
         'enable_dl: On (Can bypass disable_functions using extension libraries; requires dl() and this option to be enabled)'),
        (r'<td class="e">allow_url_include<\/td><td class="v">On<\/td>', 'allow_url_include: On (Allows remote file inclusion)'),
        (r'<td class="e">session.use_trans_sid<\/td><td class="v">1<\/td>', 'session.use_trans_sid: 1'),
        (r'<td class="e">display_errors<\/td><td class="v">On<\/td>', 'display_errors: On'),
        (r'short_open_tag</td><td class="v">On</td>', 'short_open_tag: On (Allows the use of <? ?> tags, and <?= is equivalent to <? echo)'),
        (r'<td class="e">session\.use_only_cookies<\/td><td class="v">Off<\/td>', 'session.use_only_cookies: On'),
        (r'System </td><td class="v">(.*?)</td>', "System Information: {}"),
        (r'SCRIPT_FILENAME"]</td><td class="v">(.*?)</td>', 'Script Path: {}'),
        (r'SERVER_ADDR"]</td><td class="v">(.*?)</td>', 'Server IP Address: {}'),
        (r'disable_functions</td><td class="v">(.*?)</td>', 'Disabled Functions List: {}'),
        (r'open_basedir</td><td class="v">(.*?)</td>', 'open_basedir (Restricts user-operable files to a specific directory, but this restriction can be bypassed): {}'),
        (r'PATH"]</td><td class="v">(.*?)</td>', 'Environment Variables: {}'),
    ]
    ret = []
    for regx, msg in rules:
        r = re.search(regx, html, re.I | re.M | re.S)
        if r:
            if "{}" in msg:
                ret.append(msg.format(r.group(1)))
            else:
                ret.append(msg)
    return ret
