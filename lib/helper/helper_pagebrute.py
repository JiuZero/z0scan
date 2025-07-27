#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlparse
from lib.core.data import conf
from bs4 import BeautifulSoup as BS
import re
from lib.core.log import logger
from config.others.CmsLoginpage import rules as cmsLogin


class Parser:
    id = 0
    post_path = ''
    resp_content = ''
    form_content = ''
    username_keyword = ''
    password_keyword = ''
    cms = ''
    data = {}

    def __init__(self, requests, response):
        self.requests = requests
        self.response = response

    def run(self):
        try:
            self.get_resp_content()
            self.cms_parser()
            self.form_parser()
            self.check_login_page()
            self.captcha_parser()
            self.post_path_parser()
            self.param_parser()
        except Exception as e:
            logger.debug(f"{self.requests.url} : " + str(e))
            return False
        return True

    def cms_parser(self):
        for cms in cmsLogin.values():
            keyword = cms["keywords"]
            if keyword and (keyword in self.resp_content):
                logger.info(f"{self.requests.url} {cms['name']}-LoginPage")
                self.cms = cms

    def get_resp_content(self):
        self.resp_content = self.response.text

    def form_parser(self):
        html = self.resp_content
        result = re.findall(".*<form (.*)</form>.*", html, re.S)
        if result:
            form_data = '<form ' + result[0] + ' </form>'
            form_soup = BS(form_data, "lxml")
            self.form_content = form_soup.form
        else:
            raise Exception("Can not get form")

    def check_login_page(self):
        login_keyword_list = conf.login_keywords
        for login_keyword in login_keyword_list:
            if login_keyword in str(self.form_content).lower():
                return True
        raise Exception("Maybe not login pages")

    def captcha_parser(self):
        captcha_keyword_list = conf.captcha_keywords
        for captcha in captcha_keyword_list:
            if captcha in self.resp_content.lower():
                logger.warning(f"{captcha} in login page. Skip brute.")
                raise Exception(f"{captcha} in login page")

    def post_path_parser(self):
        url = self.requests.url
        content = self.form_content
        form_action = str(content).split('\n')[0]
        soup = BS(form_action, "lxml")
        res = urlparse(url)
        action_path = soup.form['action']

        if action_path.startswith('http'):
            path = action_path
        elif action_path.startswith('/'):
            root_path = res.scheme + '://' + res.netloc
            path = root_path + action_path
        else:
            relative_path = url.rstrip(url.split('/')[-1])
            path = relative_path + action_path
        if not path:
            raise Exception("Can not get post path")
        self.post_path = path

    def param_parser(self):
        content = self.form_content
        data = {}
        username_keyword = ''
        password_keyword = ''
        for input_element in content.find_all('input'):
            if input_element.has_attr('name'):
                parameter = input_element['name']
            else:
                parameter = ''
            if input_element.has_attr('value'):
                value = input_element['value']
            else:
                value = "5920"
            if parameter:
                data[parameter] = value
        # 提取username_keyword,password_keyword
        for parameter in data:
            if not username_keyword and parameter != password_keyword:
                for keyword in conf.username_keywords:
                    if keyword in parameter.lower():
                        username_keyword = parameter
                        break
            if not password_keyword and parameter != username_keyword:
                for keyword in conf.password_keywords:
                    if keyword in parameter.lower():
                        password_keyword = parameter
                        break
        # 弹出reset
        for i in ['reset']:
            for r in list(data.keys()):
                if i in r.lower():
                    data.pop(r)
        if username_keyword and password_keyword:
            self.username_keyword = username_keyword
            self.password_keyword = password_keyword
            self.data = data
        else:
            return False
        return True
