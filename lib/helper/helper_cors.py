#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# Reference: https://github.com/chenjj/CORScanner
# JiuZero  2025/5/23

import requests, tldextract
try:
    from urllib.parse import urlparse
except Exception as e:
    from urlparse import urlparse
    
def is_cors_permissive(self, test_origin, test_url):
    msg = self.check_cors_policy(test_origin, test_url)
    if msg != None:
        return msg
    return False

def check_cors_policy(self, test_origin, test_url):
    resp = self.send_req(test_url, test_origin)
    resp_headers = self.get_resp_headers(resp)
    status_code = resp.status_code if resp is not None else None
    if resp_headers == None:
        return None
    parsed = urlparse(str(resp_headers.get("access-control-allow-origin")))
    if test_origin != "null":
        resp_origin = parsed.scheme + "://" + parsed.netloc.split(':')[0]
    else:
        resp_origin = str(resp_headers.get("access-control-allow-origin"))
    msg = None
    # test_origin does not have to be case sensitive
    if test_origin.lower() == resp_origin.lower():
        credentials = "false"
        if resp_headers.get("access-control-allow-credentials") == "true":
            credentials = "true"
        # Set the msg
        msg = {
            "resp": resp,
            "credentials": credentials,
            "origin": test_origin,
            "status_code" : status_code
        }
    return msg
    
def send_req(self, url, origin):
    try:
        headers = {
            'Origin':
            origin,
            'Cache-Control':
            'no-cache',
            'User-Agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
        }
        # self-signed cert OK, follow redirections
        resp = requests.get(url, headers=headers, verify=False, allow_redirects=True)
        # remove cross-domain redirections, which may cause false results
        first_domain = tldextract.extract(url).registered_domain
        last_domain = tldextract.extract(resp.url).registered_domain
        if(first_domain.lower() != last_domain.lower()):
            resp = None
    except Exception as e:
        resp = None
    return resp

def get_resp_headers(self, resp):
    if resp == None:
        return None
    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    return resp_headers