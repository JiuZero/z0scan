#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/15
# JiuZero 2025/6/16

import re
import string
from urllib.parse import unquote

import requests

from api import random_str, generateResponse, HTTPMETHOD, PLACE, VulType, Type, conf, PluginBase, KB
from lib.core.settings import XSS_EVAL_ATTITUDES, TOP_RISK_GET_PARAMS
from helper.htmlparser import SearchInputInResponse, random_upper, getParamsFromHtml
from helper.jscontext import SearchInputInScript


class Z0SCAN(PluginBase):
    name = 'xss'
    desc = "JS Semantic-based XSS Scanning"
    version = "2025.6.16"
    risk = 1

    def init(self):
        self.result = self.generate_result()

    def audit(self):
        if conf.level == 0 or self.fingerprints.waf:
            return
        parse_params = set(getParamsFromHtml(self.response.text))
        resp = self.response.text
        params_data = {}
        self.init()
        iterdatas = []
        positions = [PLACE.NORMAL_DATA, PLACE.PARAM]
        if conf.level == 3: positions += [PLACE.COOKIE]
        if self.requests.method == HTTPMETHOD.GET:
            parse_params = (parse_params | TOP_RISK_GET_PARAMS) - set(self.requests.params.keys())
            for key in parse_params:
                params_data[key] = random_str(6)
            params_data.update(self.requests.params)
            resp = requests.get(self.requests.netloc, params=params_data, headers=self.requests.headers).text
            for k, v in params_data.items():
                for position in positions:
                    iterdatas += [(k, v, position)]
        elif self.requests.method == HTTPMETHOD.POST:
            parse_params = (parse_params) - set(self.requests.data.keys())
            for key in parse_params:
                params_data[key] = random_str(6)
            params_data.update(self.requests.data)
            resp = requests.post(self.requests.url, data=params_data, headers=self.requests.headers).text
            iterdatas = self.generateItemdatas()
            for k, v in params_data.items():
                for position in positions:
                    iterdatas += [(k, v, position)]

        for iterdata in iterdatas:
            k, v, position = iterdata
            # 先不支持uri上的xss，只支持get post cookie上的xss
            if position == PLACE.URL:
                continue
            v = unquote(v)
            if v not in resp:
                continue
            # 探测回显
            xsschecker = "0x" + random_str(6, string.digits + "abcdef")
            payload = self.insertPayload({
                "key": k,
                "payload": xsschecker,
                "position": position
                })
            r1 = self.req(position, payload)
            if not re.search(xsschecker, r1.text, re.I):
                continue
            html_type = r1.headers.get("Content-Type", "").lower()
            XSS_LIMIT_CONTENT_TYPE = conf.xss_limit_content_type
            if XSS_LIMIT_CONTENT_TYPE and 'html' not in html_type:
                continue
            # 反射位置查找
            locations = SearchInputInResponse(xsschecker, r1.text)
            if len(locations) == 0:
                # 找不到反射位置，找下自己原因?
                flag = random_str(5)
                _payload = "<{}//".format(flag)
                payload = self.insertPayload({
                    "key": k,
                    "payload": _payload,
                    "position": position
                    })
                req = self.req(position, payload)
                if _payload in req.text:
                    self.result.main({
                        "type": Type.REQUEST,
                        "url": self.requests.url, 
                        "vultype": VulType.XSS,
                        "show": {
                            "Position": f"{position} >> {k}",
                            "Payload": "<svg onload=alert`1`//", 
                            "Tips": "The HTML code is not escaped.",
                            }
                        })
                    self.result.step("Request1", {
                        "request": req.reqinfo, 
                        "response": generateResponse(req),
                        "desc": "The html code is not escaped, and can be used for attack testing with <svg onload=alert`1`//, note that the return format is:" + html_type,
                        })

            for item in locations:
                _type = item["type"]
                details = item["details"]
                if _type == "html":
                    if details["tagname"] == "style":
                        _payload = "expression(a({}))".format(random_str(6, string.ascii_lowercase))
                        payload = self.insertPayload({
                            "key": k,
                            "payload": _payload,
                            "position": position
                            })
                        req = self.req(position, payload)
                        _locations = SearchInputInResponse(_payload, req.text)
                        for _item in _locations:
                            if _payload in _item["details"]["content"] and _item["details"]["tagname"] == "style":
                                self.result.main({
                                    "type": Type.REQUEST,
                                    "url": self.requests.url, 
                                    "vultype": VulType.XSS,
                                    "show": {
                                        "Position": f"{position} >> {k}",
                                        "Payload": "expression(alert(1))", 
                                        "Tips": "IE executable expressions",
                                        }
                                    })
                                self.result.step("Request1", {
                                    "request": req.reqinfo, 
                                    "response": generateResponse(req.text),
                                    "desc": "IE executable expressions: expression(alert(1))"
                                    })
                                break
                    flag = random_str(7)
                    _payload = "</{}><{}>".format(random_upper(details["tagname"]), flag)
                    truepayload = "</{}>{}".format(random_upper(details["tagname"]), "<svg onload=alert`1`>")
                    payload = self.insertPayload({
                        "key": k,
                        "payload": _payload,
                        "position": position
                        })
                    req = self.req(position, payload)
                    _locations = SearchInputInResponse(flag, req.text)
                    for i in _locations:
                        if i["details"]["tagname"] == flag:
                            self.result.main({
                                "type": Type.REQUEST,
                                "url": self.requests.url, 
                                "vultype": VulType.XSS,
                                "show": {
                                    "Position": f"{position} >> {k}",
                                    "Payload": truepayload,
                                    "Tips": "HTML tags can be closed",
                                    }
                                })
                            
                            self.result.step("Request1", {
                                "request": req.reqinfo, 
                                "response": generateResponse(req),
                                "desc": "<{}> can be closed, and {} can be used for attack testing, note that the return format is: {}".format(details["tagname"], truepayload, html_type),
                                })
                            break
                elif _type == "attibute":
                    if details["content"] == "key":
                        # test html
                        flag = random_str(7)
                        _payload = "><{} ".format(flag)
                        truepayload = "><svg onload=alert`1`>"
                        payload = self.insertPayload({
                            "key": k,
                            "payload": _payload,
                            "position": position
                            })
                        req = self.req(position, payload)
                        _locations = SearchInputInResponse(flag, req.text)
                        for i in _locations:
                            if i["details"]["tagname"] == flag:
                                self.result.main({
                                    "type": Type.REQUEST,
                                    "url": self.requests.url, 
                                    "vultype": VulType.XSS,
                                    "show": {
                                        "Position": f"{position} >> {k}",
                                        "Payload": truepayload,
                                        "Tips": "HTML tags can be closed",
                                        }
                                    })
                                self.result.step("Request1", {
                                    "request": req.reqinfo, 
                                    "response": generateResponse(req),
                                    "desc": "<{}> can be closed, and {} can be used for attack testing, note that the return format is: {}".format(details["tagname"], truepayload, html_type),
                                    })
                                break
                        # test attibutes
                        flag = random_str(5)
                        _payload = flag + "="
                        payload = self.insertPayload({
                            "key": k,
                            "payload": _payload,
                            "position": position
                            })
                        req = self.req(position, payload)
                        _locations = SearchInputInResponse(flag, req.text)
                        for i in _locations:
                            for _k, v in i["details"]["attibutes"]:
                                if _k == flag:
                                    self.result.main({
                                        "type": Type.REQUEST,
                                        "url": self.requests.url, 
                                        "vultype": VulType.XSS,
                                        "show": {
                                            "Position": f"{position} >> {k}",
                                            "Payload": "onmouseover=prompt(1)", 
                                            "Tips": "You can customize any label event",
                                            }
                                        })
                                    self.result.step("Request1", {
                                        "request": req.reqinfo, 
                                        "response": generateResponse(req),
                                        "desc": "You can customize a label event like 'onmouseover=prompt(1)', note that the return format is:" + html_type,
                                        })
                                    break
                    else:
                        # test attibutes
                        flag = random_str(5)
                        for _key in ["'", "\"", " "]:
                            _payload = _key + flag + "=" + _key
                            truepayload = "{payload} onmouseover=prompt(1) {payload}".format(payload=_key)
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            req = self.req(position, payload)
                            _occerens = SearchInputInResponse(flag, req.text)
                            for i in _occerens:
                                for _k, _v in i["details"]["attibutes"]:
                                    if _k == flag:
                                        self.result.main({
                                            "type": Type.REQUEST,
                                            "url": self.requests.url, 
                                            "vultype": VulType.XSS,
                                            "show": {
                                                "Position": f"{position} >> {k}",
                                                "Payload": truepayload,
                                                "Tips": "Quotation marks can be closed, and other events can be used to cause XSS",
                                                }
                                            })
                                        self.result.step("Request1", {
                                            "request": req.reqinfo,
                                            "response": generateResponse(req),
                                            "desc": "You can use payload: {}, note that the return format is: {}".format(truepayload, html_type)
                                            })
                                        break
                        # test html
                        flag = random_str(7)
                        for _key in [r"'><{}>", "\"><{}>", "><{}>"]:
                            _payload = _key.format(flag)
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            req = self.req(position, payload)
                            _occerens = SearchInputInResponse(flag, req.text)
                            for i in _occerens:
                                if i["details"]["tagname"] == flag:
                                    self.result.main({
                                        "type": Type.REQUEST,
                                        "url": self.requests.url, 
                                        "vultype": VulType.XSS,
                                        "show": {
                                            "Position": f"{position} >> {k}",
                                            "Payload": _key.format("svg onload=alert`1`"), 
                                            "Tips": "HTML tags can be closed",
                                            }
                                        })
                                    self.result.step("Request1", {
                                        "request": req.reqinfo, 
                                        "response": generateResponse(req),
                                        "desc": "Try for payload:{}".format(_payload.format("svg onload=alert`1`")) + ",return :" + html_type,
                                        })
                                    break
                        # 针对特殊属性进行处理
                        specialAttributes = ['srcdoc', 'src', 'action', 'data', 'href']  # 特殊处理属性
                        keyname = details["attibutes"][0][0]
                        tagname = details["tagname"]
                        if keyname in specialAttributes:
                            flag = random_str(7)
                            payload = self.insertPayload({
                                "key": k,
                                "payload": flag,
                                "position": position
                                })
                            req = self.req(position, payload)
                            _occerens = SearchInputInResponse(flag, req.text)
                            for i in _occerens:
                                if len(i["details"]["attibutes"]) > 0 and i["details"]["attibutes"][0][
                                    0] == keyname and \
                                        i["details"]["attibutes"][0][1] == flag:
                                    truepayload = flag
                                    if i["details"]["attibutes"][0][0] in specialAttributes:
                                        truepayload = "javascript:alert(1)"
                                    self.result.main({
                                        "type": Type.REQUEST,
                                        "url": self.requests.url, 
                                        "vultype": VulType.XSS,
                                        "show": {
                                            "Position": f"{position} >> {k}",
                                            "Payload": truepayload, 
                                            "Tips": "The value is controllable",
                                            }
                                        })
                                    self.result.step("Request1", {
                                        "request": req.reqinfo, 
                                        "response": generateResponse(req),
                                        "desc": "The value of {} is controllable and may be maliciously attacked, payload:{}, note that the return format is: {}".format(keyname, truepayload, html_type),
                                        })
                                    break
                        elif keyname == "style":
                            _payload = "expression(a({}))".format(random_str(6, string.ascii_lowercase))
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            req = self.req(position, payload)
                            _occerens = SearchInputInResponse(_payload, req.text)
                            for _item in _occerens:
                                if payload in str(_item["details"]) and len(_item["details"]["attibutes"]) > 0 and \
                                        _item["details"]["attibutes"][0][0] == keyname:
                                    self.result.main({
                                        "type": Type.REQUEST,
                                        "url": self.requests.url, 
                                        "vultype": VulType.XSS,
                                        "show": {
                                            "Position": f"{position} >> {k}",
                                            "Payload": "expression(alert(1))", 
                                            "Tips": "IE executable expressions",
                                            }
                                        })
                                    self.result.step("Request1", {
                                        "request": req.reqinfo, 
                                        "response": generateResponse(req.text),
                                        "desc": "IE executable expressions payload: expression(alert(1))",
                                        })
                                    break
                        elif keyname.lower() in XSS_EVAL_ATTITUDES:
                            # 在任何可执行的属性中
                            _payload = random_str(6, string.ascii_lowercase)
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            req = self.req(position, payload)
                            _occerens = SearchInputInResponse(_payload, req.text)
                            for i in _occerens:
                                _attibutes = i["details"]["attibutes"]
                                if len(_attibutes) > 0 and _attibutes[0][1] == payload and _attibutes[0][0].lower() == keyname.lower():
                                    self.result.main({
                                        "type": Type.REQUEST,
                                        "url": self.requests.url, 
                                        "vultype": VulType.XSS,
                                        "show": {
                                            "Position": f"{position} >> {k}",
                                            "Tips": "The value of the event is controllable",
                                            }
                                        })
                                    self.result.step("The value of the event is controllable", {
                                        "request": req.reqinfo, 
                                        "response": generateResponse(req),
                                        "desc": "The value of {} is controllable and may be maliciously attacked, note that the return format is: {}".format(keyname, html_type),
                                        })
                                    break
                elif _type == "comment":
                    flag = random_str(7)
                    for _key in ["-->", "--!>"]:
                        _payload = "{}<{}>".format(_key, flag)
                        truepayload = _payload.format(_key, "svg onload=alert`1`")
                        payload = self.insertPayload({
                            "key": k,
                            "payload": _payload,
                            "position": position
                            })
                        req = self.req(position, payload)
                        _occerens = SearchInputInResponse(flag, req.text)
                        for i in _occerens:
                            if i["details"]["tagname"] == flag:
                                self.result.main({
                                    "type": Type.REQUEST,
                                    "url": self.requests.url, 
                                    "vultype": VulType.XSS,
                                    "show": {
                                        "Position": f"{position} >> {k}",
                                        "Payload": truepayload,
                                        "Tips": "HTML comments can be closed",
                                        }
                                    })
                                self.result.step("Request1", {
                                    "request": req.reqinfo, 
                                    "response": generateResponse(req),
                                    "desc": "HTML comments can be closed, try for payload:{},note that the return format is: {}".format(truepayload, html_type)
                                    })
                                break
                elif _type == "script":
                    # test html
                    flag = random_str(7)
                    script_tag = random_upper(details["tagname"])
                    _payload = "</{}><{}>{}</{}>".format(script_tag, script_tag, flag, script_tag)
                    truepayload = "</{}><{}>{}</{}>".format(script_tag, script_tag, "prompt(1)", script_tag)
                    payload = self.insertPayload({
                        "key": k,
                        "payload": _payload,
                        "position": position, 
                        })
                    req = self.req(position, payload)
                    _occerens = SearchInputInResponse(flag, req.text)
                    for i in _occerens:
                        if i["details"]["content"] == flag and i["details"]["tagname"].lower() == script_tag.lower():
                            self.result.main({
                                "type": Type.REQUEST,
                                "url": self.requests.url, 
                                "vultype": VulType.XSS,
                                "show": {
                                    "Position": f"{position} >> {k}",
                                    "Payload": truepayload,
                                    "Tips": "You can create a new script tag to execute arbitrary code",
                                    }
                                })
                            self.result.step("Request1", {
                                "request": req.reqinfo, 
                                "response": generateResponse(req),
                                "desc": "You can create a new script tag to execute any code Test payload: {}, note that the return format is: {}".format(truepayload, html_type)
                                })
                            break
                    # js 语法树分析反射
                    source = details["content"]
                    _occurences = SearchInputInScript(xsschecker, source)
                    for i in _occurences:
                        _type = i["type"]
                        _details = i["details"]
                        if _type == "InlineComment":
                            flag = random_str(5)
                            _payload = "\n;{};//".format(flag)
                            truepayload = "\n;{};//".format('prompt(1)')
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            resp = self.req(position, payload).text
                            for _item in SearchInputInResponse(flag, resp):
                                if _item["details"]["tagname"] != "script":
                                    continue
                                resp2 = _item["details"]["content"]
                                output = SearchInputInScript(flag, resp2)
                                for _output in output:
                                    if flag in _output["details"]["content"] and _output["type"] == "ScriptIdentifier":
                                        self.result.main({
                                            "type": Type.REQUEST,
                                            "url": self.requests.url, 
                                            "vultype": VulType.XSS,
                                            "show": {
                                                "Position": f"{position} >> {k}",
                                                "Tips": "JS single-line comments bypass",
                                                }
                                            })
                                        self.result.step("Request1", {
                                            "request": req.reqinfo, 
                                            "response": generateResponse(req),
                                            "desc": "JS single-line comments can be bypassed by \\n, note that the return format is:" + html_type.format(truepayload),
                                            })
                                        break

                        elif _type == "BlockComment":
                            flag = "0x" + random_str(4, "abcdef123456")
                            _payload = "*/{};/*".format(flag)
                            truepayload = "*/{};/*".format('prompt(1)')
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            resp = self.req(position, _payload).text
                            for _item in SearchInputInResponse(flag, resp):
                                if _item["details"]["tagname"] != "script":
                                    continue
                                resp2 = _item["details"]["content"]
                                output = SearchInputInScript(flag, resp2)
                                for _output in output:
                                    if flag in _output["details"]["content"] and _output["type"] == "ScriptIdentifier":
                                        self.result.main({
                                            "type": Type.REQUEST,
                                            "url": self.requests.url, 
                                            "vultype": VulType.XSS,
                                            "show": {
                                                "Position": f"{position} >> {k}",
                                                "Tips": "JS block comments can be bypassed",
                                                }
                                            })
                                        self.result.step("Request1", {
                                            "request": req.reqinfo, 
                                            "response": generateResponse(req),
                                            "desc": "JS single-line comments can be bypassed by \\n, note that the return format is:" + html_type.format(truepayload),
                                            })
                                        break
                        elif _type == "ScriptIdentifier":
                            self.result.main({
                                "type": Type.REQUEST,
                                "url": self.requests.url, 
                                "vultype": VulType.XSS,
                                "show": {
                                    "Position": f"{position} >> {k}",
                                    "Payload": "prompt(1);//", 
                                    "Tips": "You can directly execute any JS command",
                                    }
                                })
                            self.result.step("Request1", {
                                "request": req.reqinfo, 
                                "response": generateResponse(req),
                                "desc": "ScriptIdentifier type test payload: prompt(1);// , note that the return format is:" + html_type,
                                })
                        elif _type == "ScriptLiteral":
                            content = _details["content"]
                            quote = content[0]
                            flag = random_str(6)
                            if quote == "'" or quote == "\"":
                                _payload = '{quote}-{rand}-{quote}'.format(quote=quote, rand=flag)
                                truepayload = '{quote}-{rand}-{quote}'.format(quote=quote, rand="prompt(1)")
                            else:
                                flag = "0x" + random_str(4, "abcdef123456")
                                _payload = flag
                                truepayload = "prompt(1)"
                            payload = self.insertPayload({
                                "key": k,
                                "payload": _payload,
                                "position": position
                                })
                            resp = self.req(position, payload).text
                            resp2 = None
                            for _item in SearchInputInResponse(_payload, resp):
                                if _payload in _item["details"]["content"] and _item["type"] == "script":
                                    resp2 = _item["details"]["content"]
                            if not resp2:
                                continue
                            output = SearchInputInScript(flag, resp2)
                            if output:
                                for _output in output:
                                    if flag in _output["details"]["content"] and _output["type"] == "ScriptIdentifier":
                                        self.result.main({
                                            "type": Type.REQUEST,
                                            "url": self.requests.url, 
                                            "vultype": VulType.XSS,
                                            "show": {
                                                "Position": f"{position} >> {k}",
                                                "Payload": truepayload,
                                                "Tips": "The script content can be set arbitrarily",
                                                }
                                            })
                                        self.result.step("Request1", {
                                            "request": req.reqinfo,
                                            "response": generateResponse(req),
                                            "desc": "Test payload:{}, note that the return format is: {}".format(truepayload, html_type),
                                            })
                                        break
        if len(self.result.detail) > 0:
            self.success(self.result)
