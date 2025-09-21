#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/10 5:28 PM
# @Author  : w8ay
# @File    : spider.py
import os
import sys
from urllib.parse import urlparse

import requests
import json
import subprocess
from lib.core.data import KB
root = os.path.dirname(os.path.realpath(__file__))
from api import modulePath, init, FakeReq, FakeResp, HTTPMETHOD, task_push_from_name, start, logger

# 爬虫文件路径
Excvpath = "/Users/boyhack/tools/crawlergo/crawlergo_darwin"

# Chrome 路径
Chromepath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def read_json(file):
    with open(file) as f:
        datas = f.readlines()
    for data in datas:
        item = json.loads(data)
        url = item["url"]
        method = item["method"]
        headers = item["headers"]
        data = item["data"]

        try:
            if method.lower() == 'post':
                req = requests.post(url, data=data, headers=headers)
                http_model = HTTPMETHOD.POST
            else:
                req = requests.get(url, headers=headers)
                http_model = HTTPMETHOD.GET
        except Exception as e:
            logger.error("request method:{} url:{} faild,{}".format(method, url, e))
            continue

        fake_req = FakeReq(req.url, {}, http_model, data)
        fake_resp = FakeResp(req.status_code, req.content, req.headers)
        task_push_from_name('loader', fake_req, fake_resp)
    logger.info("End of spider，scan start!")
    start()


def vulscan(target):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3945.0 Safari/537.36",
        "Spider-Name": "Baidu.Inc"
    }
    if target == "":
        return
    elif "://" not in target:
        target = "http://" + target
    try:
        req = requests.get(target, headers=headers, timeout=60)
        target = req.url
    except:
        return
    netloc = urlparse(target).netloc
    logger.info("Start to crawl: {}".format(target))
    cmd = [Excvpath, "-c", Chromepath, "--fuzz-path", "--robots-path", "-t", "20", "--custom-headers",
           json.dumps(headers), "--max-crawled-count", "10086", "-i", "-o", "json",
           target]
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    try:
        result = json.loads(output.decode().split("--[Mission Complete]--")[1])
    except IndexError:
        return
    if result:
        all_req_list = result["req_list"]
        logger.info("Data: {}".format(len(all_req_list)))
        for item in all_req_list:
            with open("spider_{}.json".format(netloc), "a+") as f:
                f.write(json.dumps(item) + '\n')
            url = item["url"]
            method = item["method"]
            headers = item["headers"]
            data = item["data"]

            try:
                if method.lower() == 'post':
                    req = requests.post(url, data=data, headers=headers)
                    http_model = HTTPMETHOD.POST
                else:
                    req = requests.get(url, headers=headers)
                    http_model = HTTPMETHOD.GET
            except Exception as e:
                logger.error("request method:{} url:{} faild,{}".format(method, url, e))
                continue

            fake_req = FakeReq(req.url, {}, http_model, data)
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push_from_name('loader', fake_req, fake_resp)
            logger.info("Add to target:{}".format(req.url))

    logger.info("End of spider，scan start!")
    start()
    logger.info("End of scanning.")
    logger.info("Found vulns: {}".format(KB.output.count()))


def init():
    root = modulePath()
    configure = {
        "debug": False,  # debug模式会显示更多信息
        "level": 2,
        "timeout": 30,
        "retry": 3,
        "json": "",  # 自定义输出json结果路径,
        "html": True,
        "threads": 30,  # 线程数量,
        "disable": [],
        "able": [],
        "excludes": ["google", "lastpass", '.gov.cn']  # 不扫描的网址
    }
    init(root, configure)


if __name__ == '__main__':
    target = "http://testphp.vulnweb.com/"
    init()
    # read_json("testphp_vulnweb_com.json")
    vulscan(target)
