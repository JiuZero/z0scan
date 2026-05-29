#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/4

class BasicError(Exception):
    pass


class PluginCheckError(BasicError):

    def __init__(self, info):
        super().__init__(self)
        self.errorinfo = info

    def __str__(self):
        return self.errorinfo

