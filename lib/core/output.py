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
from lib.core.data import KB, path, conf, logger
from lib.core.settings import VERSION

class OutPut(object):

    def __init__(self):
        self.collect = []
        self.lock_count = Lock()
        self.lock_file = Lock()
        self.lock_print = Lock()
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
                with open(os.path.join(path.data, "templates.tpl"), encoding='utf-8') as f:
                    with open(self.html_filename, 'w', encoding='utf-8') as f2:
                        content = f.read()
                        content = content.replace('^z0scan_version^', VERSION)
                        f2.write(content)

            with open(self.html_filename, 'a+', encoding='utf-8') as f2:
                # content = base64.b64encode(json.dumps(output).encode()).decode()
                content = quote(json.dumps(output), encoding='utf-8')
                content = "<script class='web-vulns'>webVulns.push(JSON.parse(decodeURIComponent(\"{base64}\")))</script>".format(
                    base64=content)
                f2.write(content)

        self.lock_file.release()
        self.collect.append(output)
        """
        [TIME][INFO] <www.baidu.com> | [SCAN_NAME][SCAN_TYPE]
        URL : http://www.baidu.com/a/test?id=1
        Vultype : SQL
        Position : Params > id
        Payload : ' and 1=2--+
        ....
        """
        msg = " <{}{}{}> | [{}{}{}] [{}{}{}]\n".format(logger.m, output["hostname"], logger.e, logger.m, output["type"], logger.e, logger.m, output["name"], logger.e)
        msg += "  {}URL{}      : {}\n".format(logger.cy, logger.e, output["url"])
        msg += "  {}Vultype{}  : {}\n".format(logger.cy, logger.e, output["vultype"])
        msg += "  {}Position{} : {}".format(logger.cy, logger.e, output["position"])
        if output["param"]: msg += " > {k}\n".format(k=output["param"])
        else: msg += "\n"
        if output["payload"]: msg += "  {}Payload{}  : {}".format(logger.cy, logger.e, output["payload"])
        if output["msg"]: msg += "\n  {}Msg{}     : {}".format(logger.cy, logger.e, output["msg"])
        self.lock_print.acquire()
        logger.info(msg)
        self.lock_print.release()


class ResultObject(object):
    def __init__(self, baseplugin):
        self.name = baseplugin.name # 插件名称
        self.path = baseplugin.path # 插件路径
        self.detail = collections.OrderedDict()

    def init_info(self, type: str, hostname: str, url: str, vultype: str, position: str, param=None, payload=None, msg=None):
        self.type = type
        self.hostname = hostname
        self.url = url
        self.vultype = vultype
        self.position = position
        self.param = param
        self.payload = payload
        self.msg = msg

    # 漏洞验证过程的细节展示
    def add_detail(self, name: str, request: str, response: str, msg: str):
        if name not in self.detail:
            self.detail[name] = []
        self.detail[name].append({
            "request": request,#请求
            "response": response,#响应
            "msg": msg#说明
        })

    def output(self):
        self.createtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        return {
            "name": self.name,#插件名称
            "path": self.path,#插件路径
            "type": self.type,#扫描类型
            "hostname": self.hostname,#域名
            "url": self.url,#URL
            "vultype": self.vultype,#漏洞类型
            "position": self.position,#漏洞位置
            "param": self.param,#参数
            "payload": self.payload,#Payload
            "msg": self.msg,#备注信息
            "createtime": self.createtime,#时间
            "detail": self.detail#漏洞检测过程
        }
