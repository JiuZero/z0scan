#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/28
# JiuZero 2025/5/12

import copy
import platform
import socket
import sys, re, json
import traceback
import copy
from types import SimpleNamespace
from urllib.parse import quote

import requests
import urllib3
from io import StringIO
from urllib import parse
import xml.etree.ElementTree as ET
from requests import ConnectTimeout, HTTPError, TooManyRedirects, ConnectionError
from urllib3.exceptions import NewConnectionError, PoolError
from urllib.parse import urlsplit, parse_qs, urlunsplit
from lib.core.settings import VERSION
from lib.core.common import url_dict2str
from lib.core.data import conf, KB
from lib.core.log import logger
from lib.core.exection import PluginCheckError
from lib.core.output import ResultObject
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
from lib.core.enums import POST_HINT, PLACE, HTTPMETHOD

def _flatten_json_items(data, prefix=''):
    """生成可迭代的(key_path, value)对"""
    if isinstance(data, dict):
        for k, v in data.items():
            new_prefix = f"{prefix}.{k}" if prefix else k
            yield from _flatten_json_items(v, new_prefix)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_prefix = f"{prefix}[{i}]"
            yield from _flatten_json_items(item, new_prefix)
    else:
        yield (prefix, data)

class PluginBase(object):
    fingerprints = SimpleNamespace(waf=False, os=[], programing=[], webserver=[])
    def __init__(self):
        self.type = None
        self.path = None
        self.target = None
        self.allow = None

        self.requests: FakeReq = None
        self.response: FakeResp = None

    def generate_result(self) -> ResultObject:
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
        if self.requests.data:
            if self.requests.post_hint == POST_HINT.NORMAL or self.requests.post_hint == POST_HINT.ARRAY_LIKE:
                for k, v in self.requests.post_data.items():
                    iterdatas.append([k, v, PLACE.NORMAL_DATA])
            elif self.requests.post_hint == POST_HINT.JSON:
                try:
                    json_data = json.loads(self.requests.data)
                    if isinstance(json_data, dict):
                        # 处理字典类型
                        for key_path, value in _flatten_json_items(json_data):
                            iterdatas.append([key_path, str(value), PLACE.JSON_DATA])
                    elif isinstance(json_data, list):
                        # 处理数组类型
                        for i, item in enumerate(json_data):
                            if isinstance(item, (dict, list)):
                                for key_path, value in _flatten_json_items(item, f"array[{i}]"):
                                    iterdatas.append([key_path, str(value), PLACE.JSON_DATA])
                            else:
                                iterdatas.append([f"array[{i}]", str(item), PLACE.JSON_DATA])
                    else:  # 单值情况
                        iterdatas.append(["json_value", str(json_data), PLACE.JSON_DATA])
                except json.JSONDecodeError:
                    pass
            elif self.requests.post_hint == POST_HINT.XML:
                try:
                    root = ET.fromstring(self.requests.data)
                    for elem in root.iter():
                        if elem.text and elem.text.strip():
                            iterdatas.append([elem.tag, elem.text.strip(), PLACE.XML_DATA])
                        # 带命名空间
                        for attr, value in elem.attrib.items():
                            iterdatas.append([f"{elem.tag}@{attr}", value, PLACE.XML_DATA])
                except ET.ParseError:
                    pass
            elif self.requests.post_hint == POST_HINT.JSON_LIKE:
                # 有点复杂了，后面再处理
                pass
            '''
            elif self.requests.post_hint == POST_HINT.MULTIPART:
                # 从原始数据解析multipart边界
                content_type = self.requests.headers.get('Content-Type', '')
                boundary = None
                if 'boundary=' in content_type:
                    boundary = content_type.split('boundary=')[1].split(';')[0].strip()
                if boundary:
                    parts = self.requests.data.split(f'--{boundary}')
                    for part in parts:
                        if 'name="' in part:
                            name = part.split('name="')[1].split('"')[0]
                            # 这里简单处理下，有时间再研究着改一下
                            value_part = part.split('\r\n\r\n', 1)[1].rsplit('\r\n', 1)[0]
                            iterdatas.append([name, value_part, PLACE.MULTIPART_DATA])
            '''
        if conf.scan_cookie and self.requests.cookies:
            for k, v in self.requests.cookies.items():
                iterdatas.append([k, v, PLACE.COOKIE])
        if any(re.search(r'/{}[-_/]([^-_/?#&=]+)'.format(re.escape(k)), self.requests.url, re.I) for k in conf.pseudo_static_keywords):
            for k in conf.pseudo_static_keywords:
                pattern = re.compile(r'/{}[-_/]([^-_/?#&=]+)'.format(re.escape(k)), re.I)
                match = pattern.search(self.requests.url)
                if match:
                    v = match.group(1)
                    iterdatas.append([k, v, PLACE.URL])
        return iterdatas

    def inject_json_payload(self, original_json, target_key, payload):
        """
        JSON数据payload注入核心方法
        :param original_json: 原始JSON字符串
        :param target_key: 目标键路径 (格式如 "user.name", "array[0]", "json_value")
        :param payload: 要注入的内容
        :return: 修改后的JSON对象
        """
        try:
            data = json.loads(original_json)
            def _inject(node, key_parts, payload):
                current_key = key_parts[0]
                if current_key.startswith("array["):
                    index = int(current_key[6:-1])
                    if isinstance(node, list) and index < len(node):
                        if len(key_parts) == 1:
                            node[index] = str(node[index]) + payload
                        else:
                            _inject(node[index], key_parts[1:], payload)
                elif isinstance(node, dict):
                    if current_key in node:
                        if len(key_parts) == 1:
                            node[current_key] = str(node[current_key]) + payload
                        else:
                            _inject(node[current_key], key_parts[1:], payload)
                elif current_key == "json_value" and len(key_parts) == 1:
                    return str(node) + payload
                return node
            if target_key == "json_value":
                return str(data) + payload
            else:
                key_parts = target_key.split('.')
                _inject(data, key_parts, payload)
                return data
        except json.JSONDecodeError:
            return None
    
    def inject_xml_payload(self, xml_data, target_path, payload):
        """
        XML数据payload注入处理器
        :param xml_data: 原始XML字符串
        :param target_path: 目标路径格式:
        - "elem1/elem2" (元素路径)
        - "elem@attr" (属性路径)
        - "ns:elem" (带命名空间)
        :param payload: 要注入的字符串
        :return: 修改后的Element对象
        """
        try:
            root = ET.fromstring(xml_data)
            # 命名空间处理
            ns_map = {k if k else 'default': v 
                    for _, k, v in ET.iterparse(StringIO(xml_data), events=('start-ns',))}
            # 路径解析
            if '@' in target_path:
                elem_path, attr = target_path.split('@')
                target_elems = root.findall(elem_path, namespaces=ns_map)
                for elem in target_elems:
                    if attr in elem.attrib:
                        elem.attrib[attr] += payload
            else:
                target_elems = root.findall(target_path, namespaces=ns_map)
                for elem in target_elems:
                    if elem.text is not None:
                        elem.text = elem.text.strip() + payload
            return root
        except ET.ParseError:
            return None
    
    def inject_multipart_payload(self, original_data, content_type, target_field, payload):
        """
        Multipart/form-data 数据 payload 注入处理器
        :param original_data: 原始 multipart 数据 (bytes 或 str)
        :param content_type: Content-Type 头 (包含 boundary)
        :param target_field: 目标字段名
        :param payload: 要注入的字符串
        :return: 修改后的 multipart 数据 (bytes)
        """
        if not original_data:
            return None
        # 确保数据为字节类型
        if isinstance(original_data, str):
            original_data = original_data.encode('utf-8')
        # 提取 boundary
        boundary = None
        if 'boundary=' in content_type:
            boundary = content_type.split('boundary=')[1].split(';')[0].strip()
        if not boundary:
            logger.warning("无法从Content-Type中提取boundary")
            return None
        # 分割各部分
        boundary_line = f"--{boundary}".encode()
        parts = original_data.split(boundary_line)
        modified_parts = []
        for part in parts:
            if not part.strip():
                continue
            # 解析字段名
            header_body = part.split(b'\r\n\r\n', 1)
            if len(header_body) != 2:
                modified_parts.append(part)
                continue
            headers, body = header_body
            headers = headers.decode('utf-8', errors='ignore')
            field_name = None
            if f'name="{target_field}"' in headers:
                # 找到目标字段
                body = body.rsplit(b'\r\n', 1)[0]  # 去除末尾可能的分隔符
                try:
                    # 尝试解码原始内容 (可能是文本或二进制)
                    decoded_body = body.decode('utf-8') + payload
                    body = decoded_body.encode('utf-8')
                except UnicodeDecodeError:
                    # 二进制数据直接追加
                    body = body + payload.encode('utf-8')
                # 重建 part
                part = headers.encode('utf-8') + b'\r\n\r\n' + body
            modified_parts.append(part)
        # 重建整个 multipart 数据
        new_data = boundary_line + boundary_line.join(modified_parts)
        # 确保以 boundary-- 结尾
        if not new_data.rstrip().endswith(b'--'):
            new_data += b'--\r\n'
        return new_data
    
    def insertPayload(self, datas: dict):
        key = str(datas.get("key", ""))
        value = str(datas.get("value", ""))
        payload = str(datas.get("payload", ""))
        position = str(datas.get("position", ""))
        if position == PLACE.NORMAL_DATA:
            data = copy.deepcopy(self.requests.post_data)
            data[key] = value + payload
            return data
        elif position == PLACE.PARAM:
            params = copy.deepcopy(self.requests.params)
            params[key] = value + payload
            return params
        elif position == PLACE.JSON_DATA:
            modified_json = self.inject_json_payload(
                original_json=self.requests.data,
                target_key=key,
                payload=payload
            )
            if not modified_json:
                return None
            return modified_json if isinstance(modified_json, (dict, list)) else json.loads(modified_json) # json=modified
        elif position == PLACE.XML_DATA:
            modified_xml = self.inject_xml_payload(
                xml_data=self.requests.data,
                target_path=key,  # 如 "root/elem" 或 "elem@attr"
                payload=payload
            )
            if not modified_xml:
                return None
            return ET.tostring(modified_xml, encoding='unicode') # data=ET.tostring(modified_xml, encoding='unicode')
        elif position == PLACE.MULTIPART_DATA:
            modified_multipart = self.inject_multipart_payload(
                original_data=self.requests.data,
                content_type=self.requests.headers.get('Content-Type', ''),
                target_field=key,  # multipart 字段名
                payload=payload
            )
            if not modified_multipart:
                return None
            return modified_multipart # data=modified_multipart
        elif position == PLACE.COOKIE:
            cookies = copy.deepcopy(self.requests.cookies)
            cookies[key] = value + payload
            return cookies
        elif position == PLACE.URL:
            # 向伪静态注入点插入的未编码的Payload可能导致网站报错
            payload = parse.quote(payload)
            url = re.sub(r'/{}[-_/]([^-_/?#&=]+)'.format(re.escape(key), re.escape(value)),r'/{}[-_/]([^-_/?#&=]+)'.format(key, parse.quote(value + payload)), self.requests.url)
            return url

    def req(self, position, payload, allow_redirects=True):
        '''
        sess = requests.Session()
        sess.mount('http://', HTTPAdapter(max_retries=conf.retry)) 
        sess.mount('https://', HTTPAdapter(max_retries=conf.retry))     
        sess.keep_alive = False'
        '''
        r = False
        parsed = urlsplit(copy.deepcopy(self.requests.url))
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

        if not PLACE.URL:
            payload = {
                k: str(v).encode("utf-8")
                for k, v in payload.items()
            }
        
        params = copy.deepcopy(self.requests.params)
        params = "?" + "&".join(f"{k}={v}" for k, v in params.items())
        
        data = copy.deepcopy(self.requests.post_data)
        if data is not None:
            data = {
                k: str(v).encode("utf-8")
                for k, v in data.items()
            }

        if position == PLACE.PARAM:
            r = requests.get(url, params=payload, data=self.requests.post_data, headers=self.requests.headers, allow_redirects=allow_redirects)
        
        if position == PLACE.NORMAL_DATA:
            r = requests.post(url, params=params, data=payload, headers=self.requests.headers, allow_redirects=allow_redirects)
        elif position == PLACE.JSON_DATA:
            r = requests.post(url, params=params, data=payload, headers=self.requests.headers, allow_redirects=allow_redirects)
        elif position == PLACE.XML_DATA:
            r = requests.post(url, params=params, data=payload, headers=self.requests.headers, allow_redirects=allow_redirects)
        elif position == PLACE.MULTIPART_DATA:
            r = requests.post(url, params=params, data=payload, headers=self.requests.headers, allow_redirects=allow_redirects)
        elif position == PLACE.COOKIE:
            if self.requests.method == HTTPMETHOD.GET:
                r = requests.get(url, params=params, data=self.requests.post_data, headers=payload, allow_redirects=allow_redirects)
            elif self.requests.method == HTTPMETHOD.POST:
                r = requests.post(url, params=params, data=data, headers=payload, allow_redirects=allow_redirects)
        elif position == PLACE.URL:
            if self.requests.method == HTTPMETHOD.GET:
                r = requests.get(payload, params=params, data=self.requests.post_data, headers=self.requests.headers, allow_redirects=allow_redirects)
            elif self.requests.method == HTTPMETHOD.POST:
                r = requests.post(payload, params=params, data=self.requests.post_data, headers=self.requests.headers, allow_redirects=allow_redirects)
        # sess.close()
        return r
    
    def execute(self, request: FakeReq, response: FakeResp):
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
                # msg = "connect target '{0}' failed!".format(self.requests.hostname)
                return
                # Share.dataToStdout('\r' + msg + '\n\r')

        except HTTPError as e:
            msg = 'Plugin: {0} HTTPError occurs, start it over.'.format(self.requests.hostname)
            logger.warning(msg)
        except ConnectionError as e:
            msg = "connect target '{}' failed!".format(self.requests.hostname)
            logger.warning(msg)
            return
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
            logger.error(errMsg)
            logger.error(excMsg)
            sys.exit(0)
        return output
