#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4

from api import PluginBase, ResultObject, VulType, isJavaObjectDeserialization, isPHPObjectDeserialization, isPythonObjectDeserialization, Type, PLACE, conf


class Z0SCAN(PluginBase):
    name = "ObjectDeserialization"
    desc = 'ObjectDeserialization Finder'

    def condition(self):
        if 1 in conf.level:
            return True
        return False
    
    def _check(self, k, v, position):
        whats = None
        if isJavaObjectDeserialization(v):
            whats = "JavaObjectDeserialization"
        elif isPHPObjectDeserialization(v):
            whats = "PHPObjectDeserialization"
        elif isPythonObjectDeserialization(v):
            whats = "PythonObjectDeserialization"
        if whats:
            result = ResultObject(self)
            result.init_info(Type.ANALYZE, self.requests.hostname, self.requests.url, VulType.OTHER, position, param=k, payload=v, msg="Type is {}".format(whats))
            result.add_detail("Request", self.requests.raw, self.response.raw, "{} is the deserialization of {} as result".format(k, whats))
            self.success(result)

    def audit(self):
        if not self.condition():
            return
        params = self.requests.params
        data = self.requests.post_data
        cookies = self.requests.cookies

        if params:
            for k, v in params.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, PLACE.PARAM)

        if data:
            for k, v in data.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, PLACE.DATA)

        if cookies:
            for k, v in cookies.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, PLACE.HEADER)
