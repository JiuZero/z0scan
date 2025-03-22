#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : plugins.py

import copy
import platform
import socket
import sys, re
import traceback
import config
from urllib.parse import quote

import requests
import urllib3
from urllib import parse
from concurrent.futures import ThreadPoolExecutor
from requests import ConnectTimeout, HTTPError, TooManyRedirects, ConnectionError
from urllib3.exceptions import NewConnectionError, PoolError
from urllib.parse import urlsplit, parse_qs, urlunsplit
from lib.core.settings import VERSION
from lib.core.common import url_dict2str # createGithubIssue
from lib.core.data import conf, KB, logger
from lib.core.exection import PluginCheckError
from lib.core.output import ResultObject
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
from lib.core.common import splitUrlPath, updateJsonObjectFromStr
from lib.core.enums import POST_HINT, PLACE, HTTPMETHOD

class PluginBase(object):

    def __init__(self):
        self.type = None
        self.path = None
        self.target = None
        self.requests: FakeReq = None
        self.response: FakeResp = None

    def new_result(self) -> ResultObject:
        return ResultObject(self)

    def success(self, msg: ResultObject):
        if isinstance(msg, ResultObject):
            msg = msg.output()
        elif isinstance(msg, dict):
            pass
        else:
            raise PluginCheckError('self.success() not ResultObject')
        KB.output.success(msg)

    def checkImplemennted(self):
        name = getattr(self, 'name')
        if not name:
            raise PluginCheckError('name')

    def audit(self):
        raise NotImplementedError

    def generateItemdatas(self):
        """
        iterdatas = [
            ["id", "1", "URL"],
            ["user", "admin", "PARAMS"]
        ]
        """
        iterdatas = []
        if self.requests.params:
            for k, v in self.requests.params.items():
                iterdatas.append([k, v, PLACE.PARAM])
        if self.requests.post_data:
            for k, v in self.requests.post_data.items():
                iterdatas.append([k, v, PLACE.DATA])
        if KB["SCAN_COOKIE"] and self.requests.cookies:
            for k, v in self.requests.cookies.items():
                iterdatas.append([k, v, PLACE.COOKIE])
        if any(re.search(r'/{}/?(\d+|[^/]+)'.format(re.escape(k)), self.requests.url, re.I) for k in config.PSEUDO_STATIC_KEYWORDS):
            for k in config.PSEUDO_STATIC_KEYWORDS:
                pattern = re.compile(r'/{}/?(\d+|[^/]+)'.format(re.escape(k)), re.I)
                match = pattern.search(self.requests.url)
                if match:
                    v = match.group(1)
                    iterdatas.append([k, v, PLACE.URL])
        return iterdatas

    def insertPayload(self, k, v, positon, payload, urlsafe='/\\'):
        if positon == PLACE.DATA:
            data = self.requests.post_data
            data[k] = v + payload
            return data
        elif positon == PLACE.PARAM:
            params = self.requests.params
            for key in self.requests.params.keys():
                if k == key:
                    params[k] = v + payload
                return params
        elif positon == PLACE.COOKIE:
            cookies = self.requests.cookies
            for key in self.requests.cookies.keys():
                if k == key:
                    cookies[k] = v + payload
                return cookies
        elif positon == PLACE.URL:
            # 未URL编码向伪静态注入点插入的Payload可能导致网站报错
            payload = parse.quote(payload)
            url = re.sub(r'/{}/{}'.format(re.escape(k), re.escape(v)),r'/{}/{}'.format(k, parse.quote(v + payload)), self.requests.url)
            return url
    
    def req(self, position, payload):
        r = False
        if position == PLACE.PARAM:
            url, payload = self.merged_params_requests(self.requests.url, payload)
            r = requests.get(url, payload, data=self.requests.post_data, headers=self.requests.headers)
        elif position == PLACE.DATA:
            # if hint == POST_HINT.NORMAL:
            url, params = self.merged_params_requests(self.requests.url, self.requests.params)
            r = requests.post(url, params=params, data=payload, headers=self.requests.headers)
        if position == PLACE.COOKIE:
            url, params = self.merged_params_requests(self.requests.url, payload)
            if self.requests.method == HTTPMETHOD.GET:
                r = requests.get(url, params=params, data=self.requests.post_data, headers=payload)
            elif self.requests.method == HTTPMETHOD.POST:
                r = requests.post(url, params=params, data=self.requests.post_data, headers=payload)
        elif position == PLACE.URL:
            payload, params = self.merged_params_requests(payload, self.requests.params)
            if self.requests.method == HTTPMETHOD.GET:
                r = requests.get(payload, params=params, data=self.requests.post_data, headers=self.requests.headers)
            elif self.requests.method == HTTPMETHOD.POST:
                r = requests.post(payload, params=params, data=self.requests.post_data, headers=self.requests.headers)
        return r
    
    def merged_params_requests(self, url, payload):
        # 合并URL中的查询参数与payload参数，避免重复
        # (原因是实战过程中发现部分站点在遇到查询参数重复时会非正常响应)
        url_parts = urlsplit(url)
        original_query = parse_qs(url_parts.query)
        payload_query = {}
        for key, value in payload.items():
            if isinstance(value, list):
                payload_query[key] = value
            else:
                payload_query[key] = [value]
        merged_query = original_query.copy()
        merged_query.update(payload_query)
        new_url_parts = url_parts._replace(query=None)
        new_url = urlunsplit(new_url_parts)
        return new_url, merged_query
    
    def execute(self, request: FakeReq, response: FakeResp):
        self.target = ''
        self.requests = request
        self.response = response
        output = None
        try:
            output = self.audit()
        except NotImplementedError:
            msg = 'Plugin: {0} not defined "{1} mode'.format(self.name, 'audit')
            logger.error(msg)

        except (ConnectTimeout, requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError, socket.timeout):
            retry = conf.retry
            while retry > 0:
                msg = 'Plugin: {0} timeout, start it over.'.format(self.name)
                if KB["DEBUG"]:
                    logger.debug(msg)
                try:
                    output = self.audit()
                    break
                except (
                        ConnectTimeout, requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError,
                        socket.timeout):
                    retry -= 1
                except Exception:
                    return
            else:
                msg = "connect target '{0}' failed!".format(self.target)
                # Share.dataToStdout('\r' + msg + '\n\r')

        except HTTPError as e:
            msg = 'Plugin: {0} HTTPError occurs, start it over.'.format(self.name)
            # Share.dataToStdout('\r' + msg + '\n\r')
        except ConnectionError:
            msg = "connect target '{0}' failed!".format(self.target)
            # Share.dataToStdout('\r' + msg + '\n\r')
        except requests.exceptions.ChunkedEncodingError:
            pass
        except ConnectionResetError:
            pass
        except TooManyRedirects as e:
            pass
        except NewConnectionError as ex:
            pass
        except PoolError as ex:
            pass
        except UnicodeDecodeError:
            # 这是由于request redirect没有处理编码问题，导致一些网站编码转换被报错,又不能hook其中的关键函数
            # 暂时先pass这个错误
            pass
        except UnicodeError:
            # bypass unicode奇葩错误
            pass
        except (
                requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema,
                requests.exceptions.ContentDecodingError):
            # 出现在跳转上的一个奇葩错误，一些网站会在收到敏感操作后跳转到不符合规范的网址，request跟进时就会抛出这个异常
            # 奇葩的ContentDecodingError
            pass
        except KeyboardInterrupt:
            raise
        except Exception:
            errMsg = "Z0SCAN plugin traceback:\n"
            errMsg += "    Running version: {}\n".format(VERSION)
            errMsg += "    Python version: {}\n".format(sys.version.split()[0])
            errMsg += "    Operating system: {}\n".format(platform.platform())
            if request:
                errMsg += '\n\nrequest raw:\n'
                errMsg += request.raw
            excMsg = traceback.format_exc()
            logger.error('\r' + errMsg + '\n\r')
            logger.error('\r' + excMsg + '\n\r')
            '''
            if createGithubIssue(errMsg, excMsg):
                logger.info('A issue has reported')'
            '''

        return output
