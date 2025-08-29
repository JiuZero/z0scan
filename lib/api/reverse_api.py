#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/6

import time
from lib.core.data import conf
import requests, random, string
from lib.core.log import logger

def random_str(length=10, chars=string.ascii_lowercase):
    return ''.join(random.sample(chars, length))

class reverseApi(object):

    def __init__(self):
        self.sleep = conf.reverse.get("sleep")
        
    def check(self, token) -> list:
        time.sleep(self.sleep)
        api = "http://{}:{}/" + "_/search?q=" + token
        try:
            resp = requests.get(api).json()
        except Exception as e:
            logger.error("Reverse check faild. Please check for reverse service.")
            resp = {}

        return resp

    def show(self) -> list:
        '''
        显示回显平台所有记录
        :return:
        '''
        api = "http://{}:{}/" + "_/search?q=" + "all"
        resp = requests.get(api).json()
        return resp
    
    def generate(self, type):
        token = random_str(6)
        if type == "http":
            fullname = "http://{}:{}/?d={}".format(conf.reverse.get("http_ip"), conf.reverse.get("http_port"), token)
        if type == "http2":
            token = "z0_" + random_str(6)
            fullname = "http://{}:{}/{}".format(conf.reverse.get("http_ip"), conf.reverse.get("http_port"), token)
        elif type == "dns":
            fullname = "{}.{}".format(token, conf.reverse.get("dns_domain"))
        elif type == "rmi":
            fullname = "rmi://{}:{}/{}".format(conf.reverse.get("rmi_ip"), conf.reverse.get("rmi_port"), token)
        elif type == "ldap":
            fullname = "ldap://{}:{}/{}".format(conf.reverse.get("ldap_ip"), conf.reverse.get("ldap_port"), token)
        return token, fullname
