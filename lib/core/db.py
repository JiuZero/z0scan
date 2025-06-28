#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/2/23

import sqlite3, os, sys, re
from lib.core.log import logger

def regexp(pattern, string):
    return re.match(pattern, string) is not None

def insertdb(table: str, columns_values: dict):
    columns = ""
    values = ""
    for column, value in columns_values.items():
        columns += str(column) + ","
        values += "'" + str(value) + "',"
    columns = columns.rstrip(",")
    values = values.rstrip(",")
    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()
    query = 'INSERT INTO {} ({}) VALUES({})'.format(table, columns, values)
    logger.debug("The DB Query: {}".format(query), origin="db", level=3)
    cursor.execute(query)
    conn.commit()
    conn.close()
    return True

def selectdb(table: str, columns:str, where=None):
    try:
        conn = sqlite3.connect(dbpath)
        cursor = conn.cursor()
        query = "SELECT {} FROM {}".format(columns, table)
        if where:
            query += " WHERE {}".format(where)
        logger.debug("The DB Query: {}".format(query), origin="db", level=3)
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result
    except sqlite3.OperationalError as e:
        logger.warning(e)
        return False
    except Exception as e:
        logger.error(e)
        sys.exit(0)
    
    
def initdb(root):
    global dbpath
    dbpath = os.path.join(root, 'lib', 'data', 'z0scan.db')
    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()
    # WAF记录（仅存在WAF的域名会被记录在里面）
    cursor.execute('CREATE TABLE IF NOT EXISTS WAFHISTORY(HOSTNAME TEXT, WAFNAME TEXT)')
    # 缓存记录（记录每次项目启动后扫描过的URL及关联信息）
    try:
        cursor.execute('DELETE FROM CACHE')
    except Exception as e:
        logger.debug(e, origin="db", level=3)
    cursor.execute('CREATE TABLE IF NOT EXISTS CACHE(HOSTNAME TEXT, URL TEXT, PARAMS TEXT)')
    conn.commit()
    conn.close()
    return True