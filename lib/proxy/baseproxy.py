#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Reference: https://github.com/qiyeboy/BaseProxy
# qiye 2018/6/15
# JiuZero 2025/7/5

import http
import os
import platform
import select
import sys
import time
import traceback
import zlib
import threading
import asyncio
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import ssl
import socket
from ssl import SSLError
from urllib.parse import urlparse, ParseResult, urlunparse

import chardet
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, TYPE_RSA, PKey, X509, X509Extension, dump_privatekey, \
    dump_certificate, load_privatekey, X509Req

from lib.core.settings import VERSION
from lib.core.log import dataToStdout, logger
from lib.core.data import path, conf, KB
from lib.core.enums import HTTPMETHOD
from lib.parse.parse_request import FakeReq
from lib.parse.parse_response import FakeResp
import socks as socks5

__all__ = [
    'CAAuth',
    'ProxyHandle',
    'InterceptPlug',
    'MitmProxy',
    'AsyncMitmProxy',
    'Request',
    'Response',
    'HttpTransfer'
]


class HttpTransfer(object):
    version_dict = {9: 'HTTP/0.9', 10: 'HTTP/1.0', 11: 'HTTP/1.1'}

    def __init__(self):
        self.hostname = None
        self.port = None

        # 这是请求
        self.command = None
        self.path = None
        self.request_version = None

        # 这是响应
        self.response_version = None
        self.status = None
        self.reason = None

        self._headers = None

        self._body = b''

    def parse_headers(self, headers_str):
        header_list = headers_str.rstrip("\r\n").split("\r\n")
        headers = {}
        for header in header_list:
            if ": " in header:
                key, value = header.split(": ", 1)
                headers[key.lower()] = value
        return headers

    def to_data(self):
        raise NotImplementedError("Function to_data need override")

    def set_headers(self, headers):
        headers_tmp = {}
        for k, v in headers.items():
            if k.lower() == "accept-encoding" and "br" in v:
                vl = [x.strip(" ") for x in v.split(",")]
                v = ", ".join(list(filter(lambda x: x != "br", vl)))
            headers_tmp[k] = v
        self._headers = headers_tmp

    def build_headers(self):
        return '\r\n'.join(f"{k}: {v}" for k, v in self._headers.items()) + '\r\n\r\n'

    def get_header(self, key):
        if isinstance(key, str) and self._headers:
            return self._headers.get(key.lower(), None)
        return None

    def get_headers(self):
        return self._headers

    def set_header(self, key, value):
        if isinstance(key, str) and isinstance(value, str):
            self._headers[key] = value
            return
        raise Exception("Parameter should be str")

    def get_body_data(self):
        return self._body

    def set_body_data(self, body):
        if isinstance(body, bytes):
            self._body = body
            self.set_header("Content-Length", str(len(body)))
            return
        raise Exception("Parameter should be bytes")


class Request(HttpTransfer):

    def __init__(self, req):
        HttpTransfer.__init__(self)

        self.hostname = req.hostname
        self.port = req.port
        self.command = req.command
        self.path = req.path
        self.https = False
        self.request_version = req.request_version

        self.post_hint = None
        self.post_data = None

        self._parsed_url = urlparse(self.path)
        self.netloc = self._parsed_url.netloc
        self.params = self._parsed_url.params

        self.cookies = None

        self.set_headers(req.headers)

        if self.get_header('Content-Length'):
            self.set_body_data(req.rfile.read(int(self.get_header('Content-Length'))))

    def to_data(self):
        req_data = f"{self.command} {self.path} {self.request_version}\r\n"
        req_data += self.build_headers()
        req_data = req_data.encode("utf-8", errors='ignore')
        req_data += self.get_body_data()
        return req_data

    def set_https(self, result=False):
        self.https = result


class Response(HttpTransfer):

    def __init__(self, request, proxy_socket):
        HttpTransfer.__init__(self)

        self.request = request
        self._body_str = None
        self.decoding = None
        self.language = self.system = self.webserver = None

        self.h = HTTPResponse(proxy_socket)
        self.h.begin()
        
        if 'Transfer-Encoding' in self.h.msg:
            del self.h.msg['Transfer-Encoding']
        if 'Content-Length' in self.h.msg:
            del self.h.msg['Content-Length']

        self.response_version = self.version_dict[self.h.version]
        self.status = self.h.status
        self.reason = self.h.reason
        self.set_headers(self.h.msg)

    def iter_content(self, chunk_size=64*1024):
        """流式读取响应内容，用于大文件处理"""
        try:
            while True:
                chunk = self.h.read(chunk_size)
                if not chunk:
                    break
                encoding = self.get_header("Content-Encoding") or self.get_header("content-encoding")
                yield self._decode_content_chunk(chunk, encoding)
        except (http.client.IncompleteRead, zlib.error, socket.timeout, MemoryError) as e:
            logger.error(f"Error reading response chunk: {e}")
            yield b''

    def _decode_content_chunk(self, chunk, encoding):
        """解码单个数据块"""
        if not encoding or encoding == 'identity':
            return chunk
        elif encoding in ('gzip', 'x-gzip'):
            try:
                return zlib.decompress(chunk, 16 + zlib.MAX_WBITS)
            except zlib.error:
                return chunk
        elif encoding == 'deflate':
            try:
                return zlib.decompress(chunk, -zlib.MAX_WBITS)
            except zlib.error:
                return chunk
        return chunk

    def get_body_str(self, decoding=None):
        if self._body_str is None:
            body_data = b''.join(self.iter_content())
            if self.get_header('Content-Type') and ('text' in self.get_header('Content-Type') or 'javascript' in self.get_header('Content-Type')):
                self.decoding = chardet.detect(body_data)['encoding']
                if self.decoding:
                    try:
                        self._body_str = body_data.decode(self.decoding)
                    except Exception:
                        self._body_str = body_data.decode('utf-8', errors='ignore')
                        self.decoding = 'utf-8'
                else:
                    self._body_str = body_data.decode('utf-8', errors='ignore')
                    self.decoding = 'utf-8'
            else:
                self._body_str = body_data
                self.decoding = None
        
        if decoding and decoding != self.decoding and self.decoding:
            try:
                return b''.join(self.iter_content()).decode(decoding)
            except Exception:
                return self._body_str
        return self._body_str

    def set_body_str(self, body_str, encoding=None):
        if isinstance(body_str, str):
            if encoding:
                self.set_body_data(body_str.encode(encoding))
            else:
                self.set_body_data(body_str.encode(self.decoding if self.decoding else 'utf-8'))
            self._body_str = body_str
            return
        raise Exception("Parameter should be str")

    def to_data(self):
        res_data = f"{self.response_version} {self.status} {self.reason}\r\n"
        res_data += self.build_headers()
        res_data = res_data.encode(self.decoding if self.decoding else 'utf-8', errors='ignore')
        res_data += b''.join(self.iter_content())
        return res_data


class CAAuth(object):
    def __init__(self, ca_file="ca.pem", cert_file='ca.crt'):
        self.ca_file_path = os.path.join(path["certs"], ca_file)
        self.cert_file_path = os.path.join(path['certs'], cert_file)
        self.cert_cache = {}
        self._gen_ca()
        self._start_cache_cleaner()

    def _gen_ca(self, again=False):
        if os.path.exists(self.ca_file_path) and os.path.exists(self.cert_file_path) and not again:
            self._read_ca(self.ca_file_path)
            return
        self.key = PKey()
        self.key.generate_key(TYPE_RSA, 2048)
        self.cert = X509()
        self.cert.set_version(2)
        self.cert.set_serial_number(1)
        self.cert.get_subject().C = 'CN'
        self.cert.get_subject().ST = 'Beijing'
        self.cert.get_subject().O = 'z0scan'
        self.cert.get_subject().CN = 'Z0Scan scanner'
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=self.cert),
        ])
        self.cert.sign(self.key, 'sha256')
        with open(self.ca_file_path, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, self.key))
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

        with open(self.cert_file_path, 'wb+') as f:
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file, 'rb').read())
        self.key = load_privatekey(FILETYPE_PEM, open(file, 'rb').read())

    def __getitem__(self, cn):
        if cn in self.cert_cache:
            return self.cert_cache[cn]
        
        cache_dir = path['certs']
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        cnp = os.path.join(cache_dir, "baseproxy_{}.pem".format(cn))

        if not os.path.exists(cnp):
            self._sign_ca(cn, cnp)
        
        self.cert_cache[cn] = cnp
        return cnp

    def _sign_ca(self, cn, cnp):
        try:
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha256')

            cert = X509()
            cert.set_version(2)
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            ss = ("DNS:%s" % cn).encode(encoding="utf-8")

            cert.add_extensions(
                [X509Extension(b"subjectAltName", False, ss)])

            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha256')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))
        except Exception as e:
            raise Exception("generate CA fail:{}".format(str(e)))

    @property
    def serial(self):
        return int("%d" % (time.time() * 1000))

    def _start_cache_cleaner(self):
        """定时清理过期证书缓存"""
        def clean():
            while True:
                time.sleep(86400)  # 24小时清理一次
                with threading.Lock():
                    for cn in list(self.cert_cache.keys()):
                        path = self.cert_cache[cn]
                        if os.path.exists(path) and os.path.getmtime(path) < time.time() - 30*86400:
                            del self.cert_cache[cn]
                            if os.path.exists(path):
                                os.remove(path)
        threading.Thread(target=clean, daemon=True).start()


class ProxyHandle(BaseHTTPRequestHandler):

    def __init__(self, request, client_addr, server):
        self.is_connected = False
        self._target = None
        self._proxy_sock = None
        self.ssl_context_cache = {}
        self.loop = asyncio.new_event_loop() if hasattr(server, 'use_async') and server.use_async else None
        super().__init__(request, client_addr, server)

    def do_CONNECT(self):
        self.is_connected = True
        self.connect_intercept()

    def proxy_connect(self):
        if not conf.get("proxy_config_bool", False):
            self._proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self._proxy_sock = socks5.socksocket()
            proxy = conf.get("proxy", {})
            if "socks5" in proxy:
                hostname, port = proxy["socks5"].split(":", 1)
                self._proxy_sock.set_proxy(socks5.SOCKS5, hostname, int(port))
            elif "socks4" in proxy:
                hostname, port = proxy["socks4"].split(":", 1)
                self._proxy_sock.set_proxy(socks5.SOCKS4, hostname, int(port))
            elif "http" in proxy:
                hostname, port = proxy["http"].split(":", 1)
                self._proxy_sock.set_proxy(socks5.HTTP, hostname, int(port))
            elif "https" in proxy:
                hostname, port = proxy["https"].split(":", 1)
                self._proxy_sock.set_proxy(socks5.HTTP, hostname, int(port))
        self._proxy_sock.settimeout(10)
        self._proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64*1024)
        self._proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64*1024)
        self._proxy_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._proxy_sock.connect((self.hostname, int(self.port)))

    async def _async_send(self, sock, data):
        """异步发送数据"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, sock.sendall, data)

    async def _async_stream_response(self, response, client_sock):
        """异步流式发送响应"""
        loop = asyncio.get_event_loop()
        # 发送响应行和头部
        response_line = f"{response.response_version} {response.status} {response.reason}\r\n"
        headers = response.build_headers()
        await self._async_send(client_sock, (response_line + headers).encode('utf-8', errors='ignore'))
        
        # 流式发送响应体
        for chunk in response.iter_content():
            await self._async_send(client_sock, chunk)

    def do_GET(self):
        if self.path == 'http://z0scan.ca/':
            self._send_ca()
            return

        try:
            if not self.is_connected:
                try:
                    self._proxy_to_dst()
                except Exception as e:
                    self.send_error(500, f'connect fail because of "{str(e)}"')
                    return
            else:
                self._target = self.ssl_host + self.path

            request = Request(self)
            if request:
                if self.is_connected:
                    request.set_https(True)
                
                # 检查缓存
                cached = self.server.get_cached_response(request)
                if cached:
                    self.request.sendall(cached)
                    return

                # 发送请求
                self._proxy_sock.sendall(request.to_data())

                # 处理响应
                response = None
                errMsg = ''
                try:
                    response = Response(request, self._proxy_sock)
                except ConnectionResetError:
                    errMsg = 'because ConnectionResetError'
                except socket.timeout:
                    errMsg = 'because socket timeout'
                except http.client.BadStatusLine as e:
                    errMsg = f'because BadStatusLine {str(e)}'

                if response:
                    try:
                        # 流式发送响应
                        if self.loop:
                            self.loop.run_until_complete(self._async_stream_response(response, self.request))
                        else:
                            # 同步流式发送
                            self.request.sendall((f"{response.response_version} {response.status} {response.reason}\r\n" + response.build_headers()).encode('utf-8', errors='ignore'))
                            for chunk in response.iter_content():
                                self.request.sendall(chunk)
                    except (BrokenPipeError, OSError):
                        pass

                    # 缓存响应
                    self.server.cache_response(request, response.to_data())

                    # 记录任务
                    netloc = "https" if request.https else "http"
                    port = request.port
                    if (netloc == "https" and port == 443) or (netloc == "http" and port == 80):
                        url = f"{netloc}://{request.hostname}{request.path}"
                    else:
                        url = f"{netloc}://{request.hostname}:{port}{request.path}"
                    method = getattr(HTTPMETHOD, request.command.upper(), request.command)
                    req = FakeReq(url, request.get_headers(), method, request.get_body_data().decode('utf-8', errors='ignore'))
                    resp = FakeResp(response.status, b''.join(response.iter_content()), response.get_headers())
                    KB['task_queue'].put(('loader', req, resp))
                else:
                    self.send_error(404, f'response is None {errMsg}')
            else:
                self.send_error(404, 'Request is None')
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, IOError):
            pass
        except Exception:
            errMsg = "Z0SCAN baseproxy get request traceback:\n"
            errMsg += f"Running version: {VERSION}\n"
            errMsg += f"Python version: {sys.version.split()[0]}\n"
            errMsg += f"Operating system: {platform.platform()}\n"
            if 'request' in locals():
                errMsg += '\nRequest raw:\n'
                errMsg += request.to_data().decode(errors='ignore')
            excMsg = traceback.format_exc()
            dataToStdout(errMsg)
            dataToStdout(excMsg)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def _proxy_to_ssldst(self):
        self.hostname, self.port = self.path.split(':')
        self.proxy_connect()
        self._proxy_sock = wrap_socket(self._proxy_sock)

    def _proxy_to_dst(self):
        u = urlparse(self.path)
        if u.scheme != 'http':
            raise Exception(f'Unknown scheme {repr(u.scheme)}')
        self.hostname = u.hostname
        self.port = u.port or 80
        self.path = urlunparse(
            ParseResult(scheme='', netloc='', params=u.params, path=u.path or '/', query=u.query, fragment=u.fragment))
        self.proxy_connect()

    def connect_intercept(self):
        try:
            self._proxy_to_ssldst()
            self.send_response(200, "Connection established")
            self.end_headers()

            domain = self.path.split(':')[0]
            if domain not in self.ssl_context_cache:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.server.ca[domain])
                self.ssl_context_cache[domain] = context
            
            try:
                self.request = self.ssl_context_cache[domain].wrap_socket(
                    self.request, 
                    server_side=True
                )
            except SSLError:
                return

            self.setup()
            self.ssl_host = f'https://{self.path}'
            self.handle_one_request()
        except Exception as e:
            try:
                self.send_error(500, str(e))
            except:
                return

    def connect_relay(self):
        self.hostname, self.port = self.path.split(':')
        try:
            self.proxy_connect()
        except Exception as e:
            self.send_error(500)
            return

        self.send_response(200, 'Connection Established')
        self.end_headers()

        inputs = [self.request, self._proxy_sock]
        BUFFER_SIZE = 64 * 1024

        while True:
            readable, _, errs = select.select(inputs, [], inputs, 30)
            if errs:
                break
            for r in readable:
                try:
                    data = r.recv(BUFFER_SIZE)
                    if data:
                        if r is self.request:
                            self._proxy_sock.sendall(data)
                        elif r is self._proxy_sock:
                            self.request.sendall(data)
                    else:
                        break
                except (ConnectionResetError, TimeoutError, OSError):
                    break
        self.request.close()
        self._proxy_sock.close()

    def _send_ca(self):
        cert_path = self.server.ca.cert_file_path
        with open(cert_path, 'rb') as f:
            data = f.read()

        self.send_response(200)
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.send_header('Content-disposition', 'attachment;filename=download.crt')
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


class MitmProxy(HTTPServer):

    def __init__(self, server_addr=('', 8788), request_handler_class=ProxyHandle, bind_and_activate=True, https=True, use_async=False):
        self.response_cache = {}  # 响应缓存: {key: (data, expire_time)}
        self.cache_lock = threading.RLock()
        self.req_plugs = []
        self.ca = CAAuth()
        self.https = https
        self.use_async = use_async  # 是否启用异步模式
        super().__init__(server_addr, request_handler_class, bind_and_activate)
        logger.info(f'HTTPServer is running at address{server_addr}...')

    def _generate_cache_key(self, request):
        scheme = 'https' if request.https else 'http'
        return f"{request.command}:{scheme}://{request.hostname}:{request.port}{request.path}"

    def get_cached_response(self, request):
        key = self._generate_cache_key(request)
        with self.cache_lock:
            if key in self.response_cache:
                data, expire = self.response_cache[key]
                if time.time() < expire:
                    return data
                del self.response_cache[key]
        return None

    def cache_response(self, request, data):
        if request.command != 'GET':
            return
            
        key = self._generate_cache_key(request)
        cache_control = request.get_header('Cache-Control') or ''
        max_age = 300  # 默认5分钟
        if 'max-age=' in cache_control:
            try:
                max_age = int(cache_control.split('max-age=')[1].split(',')[0])
            except:
                pass
        if any(k in cache_control for k in ('no-cache', 'no-store', 'private')):
            return

        with self.cache_lock:
            # 限制缓存大小
            if len(self.response_cache) > 1000:
                oldest = min(self.response_cache.items(), key=lambda x: x[1][1])[0]
                del self.response_cache[oldest]
            self.response_cache[key] = (data, time.time() + max_age)

    def register(self, intercept_plug):
        self.req_plugs.append(intercept_plug)


class ProxyMinIn(ThreadingMixIn):
    daemon_threads = True
    max_threads = 50  # 限制最大线程数


class AsyncMitmProxy(ProxyMinIn, MitmProxy):
    def __init__(self, *args, **kwargs):
        kwargs['use_async'] = True
        super().__init__(*args, **kwargs)


# 保持原有的wrap_socket兼容代码
try:
    from ssl import wrap_socket
except ImportError:
    def ssl_wrap_socket(sock, keyfile=None, certfile=None,
                      server_side=False, cert_reqs=ssl.CERT_NONE,
                      ssl_version=ssl.PROTOCOL_TLS, ca_certs=None,
                      do_handshake_on_connect=True,
                      suppress_ragged_eofs=True,
                      ciphers=None, server_hostname=None):
        context = ssl.SSLContext(ssl_version)
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ca_certs:
            context.load_verify_locations(cafile=ca_certs)
        context.verify_mode = cert_reqs
        if ciphers:
            context.set_ciphers(ciphers)
        return context.wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname
        )
    wrap_socket = ssl_wrap_socket