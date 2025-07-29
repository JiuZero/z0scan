#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/7

from api import generateResponse, VulType, Type, PluginBase, conf, logger, KB
import re, socket

class Z0SCAN(PluginBase):
    name = "other-hosti"
    desc = "Host Header Injection Detection"
    version = "2025.6.7"
    risk = 1
    
    def audit(self):
        if conf.level == 0 or not self.risk in conf.risk or self.name in KB.disable:
            return
        raw_request = self.requests.raw
        modified_request = re.sub(r"Host: .*?\r\n", "Host: z0scan.com\r\n", raw_request, 1)
        try:
            if self.requests.scheme == "https":
                r = self.send_request(modified_request, ssl=True)
            else:
                r = self.send_request(modified_request)
        except Exception as e:
            logger.error(f"Request failed: {e}", origin=self.name)
            return
        
        if not r:
            return
        
        success = False
        # 检查Location头
        if "Location" in r.headers and "z0scan.com" in r.headers["Location"]:
            self.report(r, "Redirect in headers")
            success = True
        
        # 检查响应体中的重定向
        if not success:
            try:
                response_body = r.read().decode('utf-8', errors='ignore')
            except Exception as e:
                logger.error(f"Failed to read response: {e}", origin=self.name)
                return
            
            patterns = [
                r"<meta[^>]*?url[\s]*?=[\s'\"]*?([^>]*?)['\"]?>",
                r"href[\s]*?=[\s]*?['\"](.*?)['\"]",
                r"window.open\(['\"](.*?)['\"]\)", 
                r"window.navigate\(['\"](.*?)['\"]\)"
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, response_body, re.I)
                for match in matches:
                    if match.strip() and "z0scan" in match:
                        self.report(r, f"Redirect in body, pattern: {pattern}, match: {match}")
                        return
    
    def send_request(self, request_data, ssl=False):
        """发送原始请求数据"""
        try:
            if ssl:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False  # 禁用主机名验证
                context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
                with socket.create_connection((self.requests.hostname, self.requests.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.requests.hostname) as ssock:
                        if isinstance(request_data, str):
                            request_data = request_data.encode('utf-8')  # 转换为 bytes
                        ssock.sendall(request_data)
                        response = ssock.recv(8192)
            else:
                with socket.create_connection((self.requests.hostname, self.requests.port)) as sock:
                    if isinstance(request_data, str):
                        request_data = request_data.encode('utf-8')
                    sock.sendall(request_data) 
                    response = sock.recv(8192)        
            return self.parse_response(response)
        except Exception as e:
            logger.error(f"Request failed: {e}", origin=self.name)
            return None
    
    def parse_response(self, raw_response):
        """解析原始响应为Response对象，处理无效状态行"""
        from io import BytesIO
        from http.client import HTTPResponse, BadStatusLine
        
        # 自定义响应类用于处理无效HTTP响应
        class SimpleResponse:
            def __init__(self, data):
                self.headers = {}
                self.msg = self  # 兼容旧接口
                self._data = data
                self._read = False
                
            def read(self, amt=None):
                if self._read:
                    return b''
                self._read = True
                return self._data
                
            def getheader(self, name, default=None):
                return default
                
            def __getitem__(self, name):
                return None
        
        try:
            class FakeSocket(BytesIO):
                def makefile(self, *args, **kwargs):
                    return self
                    
            fake_sock = FakeSocket(raw_response)
            response = HTTPResponse(fake_sock)
            response.begin()
            return response
        except BadStatusLine:
            # 处理无效状态行，返回包含原始数据的响应
            return SimpleResponse(raw_response)
        except Exception as e:
            logger.error(f"Parse response failed: {e}", origin=self.name)
            return SimpleResponse(raw_response)
    
    def report(self, response, detail):
        """生成报告"""
        result = self.generate_result()
        result.main({
            "type": Type.REQUEST,
            "url": self.requests.url,
            "vultype": VulType.REDIRECT,
            "show": {
                "Msg": detail
            }
        })
        result.step("Request", {
            "request": self.requests.raw,
            "response": generateResponse(response),
            "desc": detail
        })
        self.success(result)