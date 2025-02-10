#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/2/9
# @Author  : DeepSeek
# Fix by Jiuz0scan
# @File    : compare.py

def compare(min_str, max_str, version_str):
    if not version_str:
        return False
    
    # 将版本字符串分割为数字列表
    def split_version(version):
        return list(map(int, version.split('.')))
    
    # 比较两个版本列表的大小
    def compare(v1, v2):
        max_len = max(len(v1), len(v2))
        v1 += [0] * (max_len - len(v1))
        v2 += [0] * (max_len - len(v2))
        for i in range(max_len):
            if v1[i] < v2[i]:
                return -1
            elif v1[i] > v2[i]:
                return 1
        return 0
        
    min_ver = split_version(min_str)
    max_ver = split_version(max_str)
    version = split_version(version_str)
    
    # 检查 version >= min_ver 且 version <= max_ver
    return compare(version, min_ver) >= 0 and compare(version, max_ver) <= 0