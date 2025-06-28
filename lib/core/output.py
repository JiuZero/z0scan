#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/17

import collections
import json, os, time
from datetime import datetime
from threading import Lock
from urllib.parse import quote
from lib.core.common import md5
from lib.core.data import path, conf
from lib.core.log import logger, colors
from lib.core.settings import VERSION
from urllib.parse import urlparse

class OutPut(object):

    def __init__(self):
        self.collect = []
        self.lock_count = Lock()
        self.lock_file = Lock()
        self.result_set = set()

        folder_name = datetime.today().strftime("%m_%d_%Y")
        folder_path = os.path.join(path.output, folder_name)
        if not os.path.isdir(folder_path):
            os.mkdir(folder_path)
        if conf.json:
            self.filename = conf.json
        else:
            filename = str(int(time.time())) + ".json"
            self.filename = os.path.join(folder_path, filename)
        self.ishtml = conf.html

        html_filename = str(int(time.time())) + ".html"
        self.html_filename = os.path.join(folder_path, html_filename)

    def get_filename(self):
        return self.filename

    def get_html_filename(self):
        return self.html_filename

    def _set(self, value):
        '''
        存储相同的结果，防止重复,不存在返回真，存在返回假
        :param value:
        :return:
        '''
        if value not in self.result_set:
            self.result_set.add(value)
            return True
        return False

    def count(self):
        self.lock_count.acquire()
        count = len(self.collect)
        self.lock_count.release()
        return count

    def success(self, output: dict):
        # 计算去重md5
        md5sum = md5(str(output).encode())
        if not self._set(md5sum):
            return
        self.lock_file.acquire()
        # 写入json
        with open(self.filename, "a+") as f:
            f.write(json.dumps(output) + '\n')

        if self.ishtml:
            # 写入html
            if not os.path.exists(self.html_filename):
                with open(os.path.join(path.root, "lib", "data", "report.template"), encoding='utf-8') as f:
                    with open(self.html_filename, 'w', encoding='utf-8') as f2:
                        content = f.read()
                        content = content.replace('^z0scan_version^', VERSION)
                        f2.write(content)

            with open(self.html_filename, 'a+', encoding='utf-8') as f2:
                # content = base64.b64encode(json.dumps(output).encode()).decode()
                content = quote(json.dumps(output), encoding='utf-8')
                content = "<script class='web-vulns'>webVulns.push(JSON.parse(decodeURIComponent(\"{base64}\")))</script>".format(base64=content)
                f2.write(content)

        self.lock_file.release()
        self.collect.append(output)
        """
        [TIME][INFO] <www.baidu.com> | [SCAN_NAME][SCAN_TYPE]
        URL : http://www.baidu.com/a/test?id=1
        Vultype : SQL
        Position : Params
        Param :  id
        Payload : ' and 1=2--+
        ....
        """
        if conf.concise_output:
            logger.info("[{}{}{}][{}{}{}] {}".format(colors.cy, output["vultype"], colors.e, colors.m, output["name"], colors.e, output["url"]))
        else:
            msg = "<{}{}{}> | [{}{}{}] [{}{}{}]\n".format(colors.m, str(output["hostname"]), colors.e, colors.m, output["type"], colors.e, colors.m, output["name"], colors.e)
            msg += "{}URL{} : {}\n".format(colors.cy, colors.e, output["url"])
            msg += "{}Vultype{} : {}\n".format(colors.cy, colors.e, output["vultype"])
            if output["show"]:
                for key, value in output["show"].items():
                    msg += "{}{}{} : {}\n".format(colors.cy, key, colors.e, value)
            logger.info(msg)


class ResultObject(object):
    def __init__(self, baseplugin):
        self.name = baseplugin.name # 插件名称
        self.path = baseplugin.path # 插件路径
        self.risk = baseplugin.risk # 危害等级
        self.desc = baseplugin.desc # 插件描述
        self.detail = collections.OrderedDict()

    def main(self, datas):
        self.type = datas.get("type", None)
        self.url = datas.get("url", None)
        if self.url:
            try:
                netloc = urlparse(self.url).netloc.split(":")
            except:
                netloc = urlparse(self.url).netloc
            self.hostname = netloc[0] if isinstance(netloc, list) else netloc
        else: self.hostname = None
        self.vultype = datas.get("vultype", None)
        self.show = datas.get("show", None)
            
    # 漏洞验证过程的细节展示
    def step(self, name: str, datas):
        position = datas.get("position")
        request = datas.get("request")
        response = datas.get("response")
        desc = datas.get("desc")
        if name not in self.detail:
            self.detail[name] = []
        self.detail[name].append({
            "position": position,#功能点位置
            "request": request,#请求
            "response": response,#响应
            "desc": desc,#说明
        })

    def output(self):
        self.createtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        return {
            "name": self.name,#插件名称
            "path": self.path,#插件路径
            "risk": self.risk,#危害等级
            "desc": self.desc,#插件描述
            "type": self.type,#扫描类型
            "hostname": self.hostname,#域名
            "url": self.url,#URL
            "vultype": self.vultype,#漏洞类型
            "createtime": self.createtime,#时间
            "detail": self.detail,#漏洞检测过程
            "show": self.show,#展示关键信息
        }
