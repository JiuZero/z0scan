#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/5

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from lib.core.data import conf
from lib.core.log import logger
from lib.reverse.lib import reverse_records, reverse_lock


class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    # GET
    def do_GET(self):
        querypath = urlparse(self.path)
        path, query = querypath.path.lstrip('/'), querypath.query
        client_ip = self.client_address[0]

        if not path:
            return self.output(b'faild')
        
        if self.path.startswith("/_/search"):
            querys = query.split("=")
            if len(querys) != 2:
                if self.path.startswith("/z0_"):
                    res = {
                        "type": "http", 
                        "client": client_ip, 
                        "query": self.path, 
                        "info": path,
                        "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    }
                    reverse_lock.acquire()
                    reverse_records.append(res)
                    logger.info("Record: {}".format(json.dumps(res)), origin="HTTP")
                    reverse_lock.release()
                    return self.output(b'ok')
                return self.output(b"faild")
            # 寻找接口
            query = querys[1]
            result = []
            reverse_lock.acquire()
            for item in reverse_records:
                item_query = item["query"]
                if query in item_query or query == 'all':
                    result.append(item)
            if result:
                logger.info("Interface result: {}".format(json.dumps(result)))
            reverse_lock.release()
            return self.output(json.dumps(result).encode())
            
        res = {
            "type": "http", 
            "client": client_ip, 
            "query": self.path, 
            "info": path,
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        }
        reverse_lock.acquire()
        reverse_records.append(res)
        logger.info("Record: {}".format(json.dumps(res)), origin="HTTP")
        reverse_lock.release()
        return self.output(b'ok')

    def log_message(self, format, *args):
        pass

    def output(self, content: bytes):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content)
        return True


def http_start():
    server_address = (conf.reverse.get("http_ip"), conf.reverse.get("http_port"))
    httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
    logger.info('Running Server... visited http://{}:{}'.format(conf.reverse.get("http_ip"), conf.reverse.get("http_port")))
    httpd.serve_forever()
