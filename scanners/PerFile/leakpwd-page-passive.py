#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/15

from urllib.parse import urlparse
import requests, time
from bs4 import BeautifulSoup as BS
import re
from api import PluginBase, VulType, Type, PLACE, conf, logger, KB, generateResponse
from lib.core.settings import brute_fail_words
from lib.helper.helper_pagebrute import Parser

def get_res_length(res):
    return len(res.text)

class Z0SCAN(PluginBase):
    name = "leakpwd-page"
    desc = 'Login page user and password brute'
    version = "2025.5.15"
    risk = 2
    
    def condition(self):
        if conf.level == 0 or not 2 in conf.risk:
            return False
        result = re.findall(".*<form (.*)</form>.*", self.response.text, re.S)
        if result:
            form_data = '<form ' + result[0] + ' </form>'
            form_soup = BS(form_data, "lxml")
            self.form_content = form_soup.form
        else:
            return False
        for login_keyword in conf.login_keywords:
            if not login_keyword in str(self.form_content).lower():
                return False
        for captcha in conf.captcha_keywords:
            if captcha in self.response.text.lower():
                return False
        self.post_path_parser()

    def post_path_parser(self):
        form_action = str(self.response.text).split('\n')[0]
        soup = BS(form_action, "lxml")
        res = urlparse(self.requests.url)
        try:
            action_path = soup.form['action']
        except:
            self.parser.post_path = self.requests.url  # 当form中没有action字段时，默认地址为self.requests.url
            return

        if action_path.startswith('http'):  # action为绝对路径
            path = action_path
        elif action_path.startswith('/'):  # action为根路径
            root_path = res.scheme + '://' + res.netloc
            path = root_path + action_path
        elif action_path == '':  # action为空
            path = self.requests.url
        else:  # action为同目录下相对路径
            relative_path = self.requests.url.rstrip(self.requests.url.split('/')[-1])
            path = relative_path + action_path
        if not path:
            return
        self.parser.post_path = path

        
    def audit(self):
        self.parser = Parser(self.requests, self.response)
        if not self.parser.run():
            return
        if not self.condition:
            return
        self.error_length = self.get_error_length()
        username_dict = conf.lists["username"]
        password_dict = conf.lists["password"]
        # 常规账号密码爆破
        res, username, password = self.crack_task(username_dict, password_dict)
        # 万能密码爆破
        if (not username and not password) or conf.level == 3:
            if conf.loginpage_sqli:
                sqlin_user_dict = sqlin_pass_dict = conf.lists["sqli-password"]
                res, username, password = self.crack_task(sqlin_user_dict, sqlin_pass_dict)
        # 二次验证
        if username and password:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": self.requests.url, 
                "vultype": VulType.WEAK_PASSWORD, 
                "show": {
                    "Result": f"User/Password: {username}/{password}"
                    }
                })
            result.step("The First Test", {
                "request": res.reqinfo, 
                "response": generateResponse(res), 
                "desc": ""
                })
            res2 = self.recheck(username, password)
            if res2:
                result.step("The Second Test", {
                    "request": res2.reqinfo, 
                    "response": generateResponse(res2), 
                    "desc": ""
                    })
                self.success(result)
                return

    def crack_request(self, conn, username, password):
        data = self.parser.data
        path = self.parser.post_path
        data[self.parser.username_keyword] = username
        data[self.parser.password_keyword] = password
        res = conn.post(url=path, data=data, verify=False, allow_redirects=True)
        time.sleep(conf.brute_delay)
        res.encoding = res.apparent_encoding
        return res

    def get_error_length(self):
        conn = requests.session()
        self.conn = conn
        # pre_res = self.crack_request(conn, self.test_username, self.test_password)  # 预请求一次
        res1 = self.crack_request(conn, ["admin"], ["length_test"])
        res2 = self.crack_request(conn, ["admin"], ["length_test"])
        error_length1 = get_res_length(res1)
        error_length2 = get_res_length(res2)
        if error_length1 != error_length2:
            return False # 不为固定值
        return error_length1

    def recheck(self, username, password):
        conn = requests.session()
        # pre_res = self.crack_request(conn, self.test_username, self.test_password)  # 预请求一次
        res1 = self.crack_request(conn, ["admin"], ["length_test"])
        res2 = self.crack_request(conn, username, password)
        error_length1 = get_res_length(res1)
        error_length2 = get_res_length(res2)

        if error_length1 == error_length2 or res2.status_code == 403:
            return False
        else:
            return res2

    def crack_task(self, username_dict, password_dict):
        fail_words = brute_fail_words
        conn = self.conn
        error_length = self.error_length
        num = 0
        dic_all = len(username_dict) * len(password_dict)
        for username in username_dict:
            for password in password_dict:
                right_pass = 1
                num = num + 1
                res = self.crack_request(conn, username, password)
                html = res.text + str(res.headers)
                if self.parser.cms:
                    if self.cms["success_flag"] and (self.parser.cms["success_flag"] in html):
                        return username, password
                    elif self.parser.cms["die_flag"] and (self.parser.cms["die_flag"] in html):
                        return False, False, False
                for fail_word in fail_words:
                    if fail_word in html:
                        right_pass = 0
                        break
                if right_pass:
                    cur_length = get_res_length(res)
                    '''
                    if self.parser.username_keyword in res.text and self.parser.password_keyword in res.text:
                        continue
                    '''
                    if cur_length != error_length:
                        return res, username, password
                else:
                    continue
        return False, False, False
