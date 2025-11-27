#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/28
# JiuZero 2025/5/12

import copy
import platform
import socket
import sys, re, json, urllib, base64, threading
from typing import Tuple
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

def is_json_string(text):
    text = text.strip()
    if not text:
        return False
    if (text.startswith('{') and text.endswith('}')) or (text.startswith('[') and text.endswith(']')):
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            pass
    return False

def is_base64_encoded(text):
    try:
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        if not base64_pattern.match(text):
            return False
        decoded = base64.b64decode(text)
        decoded_str = decoded.decode('utf-8', errors='ignore')
        return decoded_str.isprintable()
    except Exception:
        return False

def decode_possible_json_value(value):
    original_value = value
    
    try:
        url_decoded = urllib.parse.unquote(original_value)
        if url_decoded != original_value and is_json_string(url_decoded):
            return json.loads(url_decoded), "url_encoded_json"
    except:
        pass
    
    try:
        if is_base64_encoded(original_value):
            base64_decoded = base64.b64decode(original_value).decode('utf-8')
            if is_json_string(base64_decoded):
                return json.loads(base64_decoded), "base64_encoded_json"
    except:
        pass
    
    if is_json_string(original_value):
        return json.loads(original_value), "raw_json"
    
    return original_value, "plain_text"

def _flatten_json_items(data, parent_key=''):
    items = []
    
    if isinstance(data, dict):
        for k, v in data.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, (dict, list)):
                items.extend(_flatten_json_items(v, new_key))
            else:
                items.append((new_key, v))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_key = f"{parent_key}[{i}]" if parent_key else f"[{i}]"
            if isinstance(item, (dict, list)):
                items.extend(_flatten_json_items(item, new_key))
            else:
                items.append((new_key, item))
    else:
        items.append((parent_key, data))
    
    return items

class PluginBase(object):
    def __init__(self):
        self.type = None
        self.path = None
        self.target = None
        self.allow = None

        self.requests: FakeReq = None
        self.response: FakeResp = None
        self.fingerprints = SimpleNamespace(waf=False, finger=[])

    def generate_result(self) -> ResultObject:
        return ResultObject(self)

    def inject_param_json_payload(self, original_param_value, target_key, payload):
        """
        处理参数中的JSON值注入
        :param original_param_value: 原始参数值 (JSON字符串)
        :param target_key: 目标键路径 (如 "uid", "user.name", "array[0]")
        :param payload: 要注入的内容
        :return: 修改后的参数值
        """
        try:
            decoded_data, encoding_type = decode_possible_json_value(original_param_value)
            
            # 如果不是JSON，直接追加payload
            if encoding_type == "plain_text":
                return original_param_value + payload
            
            def _inject_json(node, key_parts, payload):
                if not key_parts:
                    # 如果没有更多路径，在当前节点注入
                    return str(node) + payload
                
                current_key = key_parts[0]
                
                # 处理数组索引 [0]
                if current_key.startswith("[") and current_key.endswith("]"):
                    index = int(current_key[1:-1])
                    if isinstance(node, list) and index < len(node):
                        if len(key_parts) == 1:
                            node[index] = str(node[index]) + payload
                        else:
                            _inject_json(node[index], key_parts[1:], payload)
                # 处理对象属性
                elif isinstance(node, dict) and current_key in node:
                    if len(key_parts) == 1:
                        node[current_key] = str(node[current_key]) + payload
                    else:
                        _inject_json(node[current_key], key_parts[1:], payload)
                # 如果没有找到对应的键，保持原样
                return node
            
            # 如果 target_key 为空，说明是对整个 JSON 值注入
            if not target_key:
                if isinstance(decoded_data, (dict, list)):
                    return json.dumps(decoded_data) + payload
                else:
                    return str(decoded_data) + payload
            
            # 否则按路径注入
            key_parts = target_key.split('.')
            _inject_json(decoded_data, key_parts, payload)
            
            if encoding_type == "url_encoded_json":
                return json.dumps(decoded_data)
            # 重新编码
            elif encoding_type == "base64_encoded_json":
                return base64.b64encode(json.dumps(decoded_data).encode()).decode()
            else:
                return json.dumps(decoded_data)
                
        except Exception as e:
            logger.warning(f"参数JSON注入失败: {e}")
            return original_param_value + payload

    def inject_json_payload(self, original_json, target_key, payload):
        """
        JSON主体payload注入核心方法
        :param original_json: 原始JSON字符串
        :param target_key: 目标键路径 (格式如 "user.name", "array[0]", "json_value")
        :param payload: 要注入的内容
        :return: 修改后的JSON对象
        """
        try:
            data = json.loads(original_json)
            
            def _inject(node, key_parts, payload):
                if not key_parts:
                    return node
                
                current_key = key_parts[0]
                
                # 处理数组索引 array[0]
                if current_key.startswith("array[") and current_key.endswith("]"):
                    index = int(current_key[6:-1])
                    if isinstance(node, list) and index < len(node):
                        if len(key_parts) == 1:
                            node[index] = str(node[index]) + payload
                        else:
                            _inject(node[index], key_parts[1:], payload)
                # 处理普通数组索引 [0]
                elif current_key.startswith("[") and current_key.endswith("]"):
                    index = int(current_key[1:-1])
                    if isinstance(node, list) and index < len(node):
                        if len(key_parts) == 1:
                            node[index] = str(node[index]) + payload
                        else:
                            _inject(node[index], key_parts[1:], payload)
                # 处理对象属性
                elif isinstance(node, dict):
                    if current_key in node:
                        if len(key_parts) == 1:
                            node[current_key] = str(node[current_key]) + payload
                        else:
                            _inject(node[current_key], key_parts[1:], payload)
                # 处理json_value特殊情况
                elif current_key == "json_value" and len(key_parts) == 1:
                    return str(node) + payload
                
                return node
            
            # 处理整个JSON值的情况
            if target_key == "json_value":
                return str(data) + payload
            
            # 解析路径并注入
            key_parts = target_key.split('.')
            _inject(data, key_parts, payload)
            return data
            
        except json.JSONDecodeError as e:
            logger.warning(f"JSON解析失败: {e}")
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
            
            # 收集命名空间
            ns_map = {}
            for event, elem in ET.iterparse(StringIO(xml_data), events=('start-ns',)):
                prefix, uri = elem
                ns_map[prefix] = uri
            
            # 路径解析和注入
            if '@' in target_path:
                # 属性注入: elem@attr
                elem_path, attr = target_path.split('@')
                target_elems = root.findall(elem_path, namespaces=ns_map)
                for elem in target_elems:
                    if attr in elem.attrib:
                        elem.attrib[attr] += payload
            else:
                # 元素文本注入
                target_elems = root.findall(target_path, namespaces=ns_map)
                for elem in target_elems:
                    if elem.text is not None:
                        elem.text = elem.text.strip() + payload
                    else:
                        elem.text = payload
            
            return root
            
        except ET.ParseError as e:
            logger.warning(f"XML解析失败: {e}")
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
            
        try:
            # 确保数据为字节类型
            if isinstance(original_data, str):
                original_data = original_data.encode('utf-8')
            
            # 提取 boundary
            boundary = None
            if 'boundary=' in content_type:
                boundary_match = re.search(r'boundary=([^;]+)', content_type)
                if boundary_match:
                    boundary = boundary_match.group(1).strip()
            
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
                    
                # 解析头部和主体
                header_body = part.split(b'\r\n\r\n', 1)
                if len(header_body) != 2:
                    modified_parts.append(part)
                    continue
                    
                headers, body = header_body
                headers_str = headers.decode('utf-8', errors='ignore')
                
                # 检查是否是目标字段
                if f'name="{target_field}"' in headers_str:
                    # 去除末尾可能的分隔符
                    if body.endswith(b'\r\n'):
                        body = body[:-2]
                    
                    # 尝试解码并注入
                    try:
                        decoded_body = body.decode('utf-8') + payload
                        body = decoded_body.encode('utf-8')
                    except UnicodeDecodeError:
                        # 二进制数据直接追加
                        body = body + payload.encode('utf-8')
                    
                    # 重建 part
                    part = headers + b'\r\n\r\n' + body
                
                modified_parts.append(part)
            
            # 重建整个 multipart 数据
            new_data = boundary_line + boundary_line.join(modified_parts)
            
            # 确保以 boundary-- 结尾
            if not new_data.rstrip().endswith(b'--'):
                new_data += b'--\r\n'
                
            return new_data
            
        except Exception as e:
            logger.warning(f"Multipart注入失败: {e}")
            return None

    def inject_array_like_payload(self, original_data, target_key, payload):
        """
        类数组数据payload注入处理器
        :param original_data: 原始数据 (字典形式)
        :param target_key: 目标键
        :param payload: 要注入的内容
        :return: 修改后的数据
        """
        try:
            data = copy.deepcopy(original_data)
            if target_key in data:
                data[target_key] = str(data[target_key]) + payload
            return data
        except Exception as e:
            logger.warning(f"类数组数据注入失败: {e}")
            return original_data
    
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
        iterdatas = []
        # 处理URL参数 (GET参数)
        if self.requests.params:
            for k, v in self.requests.params.items():
                decoded_data, encoding_type = decode_possible_json_value(str(v))
                
                if encoding_type != "plain_text":
                    # 参数值是JSON格式
                    if isinstance(decoded_data, (dict, list)):
                        for key_path, value in _flatten_json_items(decoded_data):
                            full_key_path = f"{k}.{key_path}" if key_path else k
                            iterdatas.append([full_key_path, str(value), PLACE.PARAM_VALUE_JSON])
                    else:
                        iterdatas.append([k, str(decoded_data), PLACE.PARAM_VALUE_JSON])
                else:
                    # 普通参数值
                    iterdatas.append([k, str(v), PLACE.PARAM])

        # 处理请求体
        if self.requests.body:
            if self.requests.post_hint == POST_HINT.NORMAL:
                for k, v in self.requests.data.items():
                    decoded_data, encoding_type = decode_possible_json_value(str(v))
                    if encoding_type != "plain_text":
                        # 表单字段值是JSON格式
                        if isinstance(decoded_data, (dict, list)):
                            for key_path, value in _flatten_json_items(decoded_data):
                                full_key_path = f"{k}.{key_path}" if key_path else k
                                iterdatas.append([full_key_path, str(value), PLACE.FORM_VALUE_JSON])
                        else:
                            iterdatas.append([k, str(decoded_data), PLACE.FORM_VALUE_JSON])
                    else:
                        # 普通表单字段
                        iterdatas.append([k, str(v), PLACE.NORMAL_DATA])
            elif self.requests.post_hint == POST_HINT.ARRAY_LIKE:
                for k, v in self.requests.data.items():
                    iterdatas.append([k, str(v), PLACE.ARRAY_LIKE_DATA])
            elif self.requests.post_hint == POST_HINT.JSON:
                try:
                    json_data = json.loads(self.requests.body)
                    if isinstance(json_data, dict):
                        for key_path, value in _flatten_json_items(json_data):
                            iterdatas.append([key_path, str(value), PLACE.JSON_DATA])
                    elif isinstance(json_data, list):
                        for i, item in enumerate(json_data):
                            if isinstance(item, (dict, list)):
                                for key_path, value in _flatten_json_items(item, f"[{i}]"):
                                    iterdatas.append([key_path, str(value), PLACE.JSON_DATA])
                            else:
                                iterdatas.append([f"[{i}]", str(item), PLACE.JSON_DATA])
                    else:
                        iterdatas.append(["json_value", str(json_data), PLACE.JSON_DATA])
                except json.JSONDecodeError:
                    pass
            elif self.requests.post_hint == POST_HINT.XML:
                try:
                    root = ET.fromstring(self.requests.body)
                    for elem in root.iter():
                        if elem.text and elem.text.strip():
                            iterdatas.append([elem.tag, elem.text.strip(), PLACE.XML_DATA])
                        for attr, value in elem.attrib.items():
                            iterdatas.append([f"{elem.tag}@{attr}", value, PLACE.XML_DATA])
                except ET.ParseError:
                    pass
            elif self.requests.post_hint == POST_HINT.SOAP:
                try:
                    root = ET.fromstring(self.requests.body)
                    for elem in root.iter():
                        if elem.text and elem.text.strip():
                            iterdatas.append([elem.tag, elem.text.strip(), PLACE.SOAP_DATA])
                except ET.ParseError:
                    pass
        
        # Cookie处理
        if conf.scan_cookie and self.requests.cookies:
            for k, v in self.requests.cookies.items():
                decoded_data, encoding_type = decode_possible_json_value(str(v))
                
                if encoding_type != "plain_text":
                    if isinstance(decoded_data, (dict, list)):
                        for key_path, value in _flatten_json_items(decoded_data):
                            full_key_path = f"{k}.{key_path}" if key_path else k
                            iterdatas.append([full_key_path, str(value), PLACE.COOKIE_JSON_VALUE])
                    else:
                        iterdatas.append([k, str(decoded_data), PLACE.COOKIE_JSON_VALUE])
                else:
                    iterdatas.append([k, str(v), PLACE.COOKIE])
        
        # 伪静态参数处理
        if any(re.search(r'/{}(?:[-_/]|\.)([^-_/?#&=\.]+)'.format(re.escape(k)), self.requests.url, re.I) for k in conf.pseudo_static_keywords):
            for k in conf.pseudo_static_keywords:
                pattern = re.compile(r'/{}(?:[-_/]|\.)([^?#&]*)'.format(re.escape(k)), re.I)
                match = pattern.search(self.requests.url)
                if match:
                    v = match.group(1)
                    if '.' in v:
                        v = v.split('.')[0]
                    iterdatas.append([k, v, PLACE.URL])
        
        return iterdatas

    def insertPayload(self, datas: dict):
        key = str(datas.get("key", ""))
        value = str(datas.get("value", ""))
        payload = str(datas.get("payload", ""))
        position = str(datas.get("position", ""))
        
        # JSON值参数处理 (PARAM_VALUE_JSON, FORM_VALUE_JSON, COOKIE_JSON_VALUE)
        if position in [PLACE.PARAM_VALUE_JSON, PLACE.FORM_VALUE_JSON, PLACE.COOKIE_JSON_VALUE]:
            if position == PLACE.PARAM_VALUE_JSON:
                params = copy.deepcopy(self.requests.params)
                if '.' in key:
                    param_name, json_path = key.split('.', 1)
                    original_value = params.get(param_name, "")
                    params[param_name] = self.inject_param_json_payload(original_value, json_path, payload)
                else:
                    params[key] = self.inject_param_json_payload(value, "", payload)
                return params
            
            elif position == PLACE.FORM_VALUE_JSON:
                data = copy.deepcopy(self.requests.data)
                if '.' in key:
                    param_name, json_path = key.split('.', 1)
                    original_value = data.get(param_name, "")
                    data[param_name] = self.inject_param_json_payload(original_value, json_path, payload)
                else:
                    data[key] = self.inject_param_json_payload(value, "", payload)
                return data
            
            elif position == PLACE.COOKIE_JSON_VALUE:
                cookies = copy.deepcopy(self.requests.cookies)
                if '.' in key:
                    param_name, json_path = key.split('.', 1)
                    original_value = cookies.get(param_name, "")
                    cookies[param_name] = self.inject_param_json_payload(original_value, json_path, payload)
                else:
                    cookies[key] = self.inject_param_json_payload(value, "", payload)
                return cookies
        
        # 常规参数处理
        elif position == PLACE.NORMAL_DATA:
            data = copy.deepcopy(self.requests.data)
            data[key] = value + payload
            return data
        
        elif position == PLACE.PARAM:
            params = copy.deepcopy(self.requests.params)
            params[key] = value + payload
            return params
        
        elif position == PLACE.ARRAY_LIKE_DATA:
            data = copy.deepcopy(self.requests.data)
            data[key] = value + payload
            return data
        
        # JSON主体处理
        elif position == PLACE.JSON_DATA:
            modified_json = self.inject_json_payload(self.requests.body, key, payload)
            if not modified_json:
                return None
            return modified_json if isinstance(modified_json, (dict, list)) else json.loads(modified_json)
        
        # XML处理
        elif position == PLACE.XML_DATA:
            modified_xml = self.inject_xml_payload(self.requests.body, key, payload)
            if not modified_xml:
                return None
            return ET.tostring(modified_xml, encoding='unicode')
        
        elif position == PLACE.SOAP_DATA:
            modified_xml = self.inject_xml_payload(self.requests.body, key, payload)
            if not modified_xml:
                return None
            return ET.tostring(modified_xml, encoding='unicode')
        
        # Multipart处理
        elif position == PLACE.MULTIPART_DATA:
            modified_multipart = self.inject_multipart_payload(
                self.requests.body,
                self.requests.headers.get('Content-Type', ''),
                key,
                payload
            )
            if not modified_multipart:
                return None
            return modified_multipart
        
        # Cookie处理
        elif position == PLACE.COOKIE:
            cookies = copy.deepcopy(self.requests.cookies)
            cookies[key] = value + payload
            return cookies
        
        # URL处理
        elif position == PLACE.URL:
            payload_encoded = urllib.parse.quote(payload)
            pattern = r'(/{}(?:[-_/]|\.))([^?#&]*)'.format(re.escape(key))
            
            def replacement(match):
                separator = match.group(1)
                original_value = match.group(2)
                if '.' in original_value:
                    base_value, extension = original_value.split('.', 1)
                    return '{}{}{}.{}'.format(separator, base_value, payload_encoded, extension)
                else:
                    return '{}{}{}'.format(separator, original_value, payload_encoded)
            
            # 解析原始URL，只修改路径部分，保留原始查询参数
            parsed_url = urlsplit(self.requests.url)
            modified_path = re.sub(pattern, replacement, parsed_url.path, flags=re.I)
            
            # 重建URL，保留原始查询参数
            url = urlunsplit((
                parsed_url.scheme,
                parsed_url.netloc,
                modified_path,
                parsed_url.query,  # 保留原始查询参数
                parsed_url.fragment
            ))
            return url

        return None

    def req(self, position, payload, allow_redirects=True, quote=True):
        try:
            parsed = urlsplit(copy.deepcopy(self.requests.url))
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

            params = copy.deepcopy(self.requests.params)
            data = copy.deepcopy(self.requests.data)

            # JSON值参数处理
            if position in [PLACE.PARAM_VALUE_JSON, PLACE.FORM_VALUE_JSON, PLACE.COOKIE_JSON_VALUE]:
                if position == PLACE.PARAM_VALUE_JSON:
                    return requests.get(url, params=payload, data=self.requests.data, 
                                    headers=self.requests.headers, allow_redirects=allow_redirects)
                elif position == PLACE.FORM_VALUE_JSON:
                    return requests.post(url, params=params, data=payload, 
                                    headers=self.requests.headers, allow_redirects=allow_redirects)
                elif position == PLACE.COOKIE_JSON_VALUE:
                    headers = copy.deepcopy(self.requests.headers)
                    if 'Cookie' in headers:
                        del headers['Cookie']
                    headers.update(payload)
                    if self.requests.method == HTTPMETHOD.GET:
                        return requests.get(url, params=params, headers=headers, 
                                        allow_redirects=allow_redirects)
                    elif self.requests.method == HTTPMETHOD.POST:
                        return requests.post(url, params=params, data=data, 
                                        headers=headers, allow_redirects=allow_redirects)
            
            # 常规参数处理
            elif position == PLACE.PARAM:
                return requests.get(url, params=payload, data=self.requests.data, 
                                headers=self.requests.headers, allow_redirects=allow_redirects)
            
            elif position in [PLACE.NORMAL_DATA, PLACE.ARRAY_LIKE_DATA]:
                return requests.post(url, params=params, data=payload, 
                                headers=self.requests.headers, allow_redirects=allow_redirects)
            
            # JSON主体处理
            elif position == PLACE.JSON_DATA:
                return requests.post(url, params=params, json=payload, 
                                headers=self.requests.headers, allow_redirects=allow_redirects)
            
            # XML处理
            elif position in [PLACE.XML_DATA, PLACE.SOAP_DATA]:
                return requests.post(url, params=params, data=payload, 
                                headers=self.requests.headers, allow_redirects=allow_redirects)
            
            # Multipart处理
            elif position == PLACE.MULTIPART_DATA:
                return requests.post(url, params=params, data=payload, 
                                headers=self.requests.headers, allow_redirects=allow_redirects)
            
            # Cookie处理
            elif position == PLACE.COOKIE:
                headers = copy.deepcopy(self.requests.headers)
                if 'Cookie' in headers:
                    del headers['Cookie']
                headers.update(payload)
                if self.requests.method == HTTPMETHOD.GET:
                    return requests.get(url, params=params, headers=headers, 
                                    allow_redirects=allow_redirects)
                elif self.requests.method == HTTPMETHOD.POST:
                    return requests.post(url, params=params, data=data, 
                                    headers=headers, allow_redirects=allow_redirects)
            
            # URL处理
            elif position == PLACE.URL:
                # 使用payload URL的路径和查询参数
                if self.requests.method == HTTPMETHOD.GET:
                    return requests.get(payload, 
                                    headers=self.requests.headers, 
                                    allow_redirects=allow_redirects)
                elif self.requests.method == HTTPMETHOD.POST:
                    return requests.post(payload, 
                                    data=self.requests.data, 
                                    headers=self.requests.headers, 
                                    allow_redirects=allow_redirects)
            logger.warning(f"未知的position类型: {position}")
            return None
        except Exception as e:
            logger.error(f"请求发送失败: {e}")
            return None
    
    def execute(self, _: Tuple[FakeReq, FakeResp, SimpleNamespace]):
        self.requests, self.response, self.fingerprints = _
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
            if self.requests:
                errMsg += '\n\nrequest raw:\n'
                errMsg += self.requests.raw
            excMsg = traceback.format_exc()
            logger.error(errMsg)
            logger.error(excMsg)
            sys.exit(0)
        return output

# 为PerPort适配的父类
class _PluginBase(object):
    def __init__(self):
        self.type = None
        self.path = None
        self.target = None
        self.allow = None
        
        self.host = str()
        self.sockrecv = None

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
    
    def execute(self, _):
        self.host , self.sockrecv = _
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
            logger.error(errMsg)
            sys.exit(0)
        return output

