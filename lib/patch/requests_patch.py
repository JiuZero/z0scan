#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/28
# caicai 2025/11/20
# JiuZero 2025/7/28

import copy
import ssl, random
from urllib.parse import urlparse, quote

from requests.cookies import RequestsCookieJar
from requests.models import Request
from requests.sessions import Session
from requests.sessions import merge_setting, merge_cookies
from requests.utils import get_encodings_from_content
from requests.exceptions import (MissingSchema, InvalidURL)
from requests._internal_utils import to_native_string, unicode_is_ascii
from requests.utils import (requote_uri)
from requests.compat import (urlunparse, str, bytes)
from requests.models import PreparedRequest

from urllib3 import disable_warnings
from urllib3.util import parse_url
from urllib3.exceptions import (LocationParseError)

from lib.core.settings import KEY_UNQUOTE
from lib.core.red import gredis
from lib.core.common import gethostportfromurl
from lib.core.block_info import block_count
from lib.core.data import conf, KB
from lib.core.log import logger


def patch_all():
    disable_warnings()
    ssl._create_default_https_context = ssl._create_unverified_context
    PreparedRequest.prepare_url = prepare_url
    Session.request = request

def request(self, method, url, 
    params=None, 
    data=None, 
    headers=None, 
    cookies=None, 
    files=None, 
    auth=None, 
    timeout=None, 
    allow_redirects=True, 
    proxies=None, 
    hooks=None, 
    stream=None, 
    verify=False, 
    cert=None, 
    json=None, 
    record=True, 
    quote=True):
    
    # record
    if isinstance(record, bool):
        if record is True:
            h, p = gethostportfromurl(url)
            block = block_count(h, p)
            if block.is_block():
                return None
    else:
        logger.warning("Requests record args need bool")
    if isinstance(quote, bool):
        if quote is False:
            url = KEY_UNQUOTE + url
    else:
        logger.error("Requests quote args need bool")
        return None

    # proxies
    if conf.get("proxies", {}) != {} and not proxies:
        proxies = conf["proxies"]
        p = random.choice(proxies.keys())
        _tmp_str = f"{p}://" + random.choice(proxies[p])
        _tmp_proxy = {
            "http": _tmp_str,
            "https": _tmp_str
        }
        proxies = _tmp_proxy
    else: proxies = {}
      
    # cookies
    merged_cookies = merge_cookies(merge_cookies(RequestsCookieJar(), self.cookies), cookies)
    
    # header
    default_header = {
        "User-Agent": conf.agent, 
        "Connection": "close"
    }
    merged_hesders = merge_setting(headers, default_header)
    
    req = Request(
        method=str(method).upper(),
        url=url,
        headers=merged_hesders,
        files=files,
        data=data or {}, 
        json=json,
        params=params or {},
        auth=auth,
        cookies=merged_cookies,
        hooks=hooks,
    )
    prep = self.prepare_request(req) # prepare_url 补丁载入

    raw = ''
    p = urlparse(url)
    _headers = copy.deepcopy(prep.headers)
    if "Host" not in _headers:
        _headers["Host"] = p.netloc
    if prep.body:
        body = prep.body.decode('utf-8') if isinstance(prep.body, bytes) else prep.body
        raw = "{}\n{}\n\n{}\n\n".format(
            prep.method + ' ' + prep.url + ' HTTP/1.1',
            '\n'.join('{}: {}'.format(k, v) for k, v in _headers.items()),
            body)
    else:
        raw = "{}\n{}\n\n".format(
            prep.method + ' ' + prep.url + ' HTTP/1.1',
            '\n'.join('{}: {}'.format(k, v) for k, v in _headers.items()))

    settings = self.merge_environment_settings(prep.url, proxies, stream, verify, cert)
    send_kwargs = {
        'timeout': timeout or conf["timeout"], 
        'allow_redirects': allow_redirects,
    }
    send_kwargs.update(settings)
    resp = self.send(prep, **send_kwargs)
    
    if record is True:
        KB["request"] += 1
        if resp != None:
            block.push_result_status(0)
        else:
            block.push_result_status(1)
            if conf.redis:
                red = gredis()
                red.hincrby("count", "request_fail", amount=1)
            KB["request_fail"] += 1
            
    if resp.encoding == 'ISO-8859-1':
        encodings = get_encodings_from_content(resp.text)
        if encodings:
            encoding = encodings[0]
        else:
            encoding = resp.apparent_encoding
        resp.encoding = encoding
    setattr(resp, 'reqinfo', raw)
    return resp

def prepare_url(self, url, params):
    """Prepares the given HTTP URL."""
    if isinstance(url, bytes):
        url = url.decode('utf8')
    else:
        url = str(url)
    url = url.lstrip()
    need_quote = True
    if url.startswith(KEY_UNQUOTE):
        need_quote = False
        url = url.replace(KEY_UNQUOTE, "")
    if ':' in url and not url.lower().startswith('http'):
        self.url = url
        return
    try:
        scheme, auth, host, port, path, query, fragment = parse_url(url)
    except LocationParseError as e:
        raise InvalidURL(*e.args)

    if not scheme:
        error = ("Invalid URL {0!r}: No schema supplied. Perhaps you meant http://{0}?")
        error = error.format(to_native_string(url, 'utf8'))
        raise MissingSchema(error)
    if not host:
        raise InvalidURL("Invalid URL %r: No host supplied" % url)
    if not unicode_is_ascii(host):
        try:
            host = self._get_idna_encoded_host(host)
        except UnicodeError:
            raise InvalidURL('URL has an invalid label.')
    elif host.startswith(u'*'):
        raise InvalidURL('URL has an invalid label.')
    netloc = auth or ''
    if netloc:
        netloc += '@'
    netloc += host
    if port:
        netloc += ':' + str(port)
    if not path:
        path = '/'
    
    # 处理参数，确保始终为字符串类型
    if need_quote:
        if isinstance(params, (str, bytes)):
            params = to_native_string(params)
        enc_params = self._encode_params(params)
    else:
        # 不需要编码时，确保params是字符串
        if params is None:
            enc_params = ''
        elif isinstance(params, dict):
            # 对于字典类型，简单拼接为key=value形式，不进行URL编码
            enc_params = '&'.join([f"{k}={v}" for k, v in params.items()])
        elif not isinstance(params, str):
            # 其他类型转换为字符串
            enc_params = str(params)
        else:
            enc_params = params
    if query is None:
        query = ''
    
    if enc_params:
        if query:
            query = f'{query}&{enc_params}'
        else:
            query = enc_params
    scheme = str(scheme) if scheme else ''
    netloc = str(netloc) if netloc else ''
    path = str(path) if path else ''
    fragment = str(fragment) if fragment else ''
    
    if need_quote:
        url = requote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
    else:
        url = urlunparse([scheme, netloc, path, None, query, fragment])
    self.url = url
