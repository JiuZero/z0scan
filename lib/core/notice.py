#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/24

import requests
from lib.core.data import conf
from wechatpy.enterprise import WeChatClient

def dingtalk(message):
    token = conf.notice["dingtalk"]['token']
    api = "robot/send"
    params = {
        "access_token": token,
    }
    data = {
        "msgtype": "text",
        "text": {
            "content": message
        }
    }
    r = requests.post("https://oapi.dingtalk.com/" + api, params=params, json=data)

def wechat(text, card=False, title="Z0Scan Notice", url="#"):
    enterprise = WeChatClient(
        corp_id=conf.notice["wechat"]['corp_id'],
        secret=conf.notice["wechat"]['secret'],
    )
    if card:
        enterprise.message.send_text_card(
            agent_id=conf.notice["wechat"]['agent_id'], 
            user_ids='', 
            tag_ids='', 
            title=title, 
            description=text, 
            url=url, 
        )
    else:
        enterprise.message.send_text(
            agent_id=conf.notice["wechat"]['agent_id'], 
            user_ids=conf.notice["wechat"]['user_list'], 
            title=title, 
            tag_ids='', 
            content=text, 
        )


def ftqq(content):
    resp = requests.post("https://sc.ftqq.com/{}.send".format(conf.notice["ftqq"]["key"]),
                  data={"text": "Z0SCAN-Push-Vlu:", "desp": content})
    if resp.json()["errno"] != 0:
        raise ValueError("Push ftqq failed, %s" % resp.text)

def notice_all(message):
    if conf.notice["wechat"]["enable"] == True:
        wechat(message)
    if conf.notice["dingtalk"]["enable"] == True:
        dingtalk(message)
    if conf.notice["ftqq"]["enable"] == True:
        ftqq(message)