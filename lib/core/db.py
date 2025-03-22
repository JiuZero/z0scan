#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/2/23

import sqlite3, os, sys, re
from lib.core.data import logger, KB
import config

def regexp(pattern, string):
    return re.match(pattern, string) is not None

def insertdb(table: str, cv: dict):
    columns = ""
    values = ""
    for c, v in cv.items():
        columns += str(c) + ","
        values += "'" + str(v) + "',"
    columns = columns.rstrip(",")
    values = values.rstrip(",")
    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()
    query = 'INSERT INTO {} ({}) VALUES({})'.format(table, columns, values)
    logger.debug("The DB Query: {}".format(query), origin="db", verify=KB["DEBUG"])
    cursor.execute(query)
    conn.commit()
    conn.close()
    return True

def selectdb(table: str, k:str, condition=None):
    try:
        conn = sqlite3.connect(dbpath)
        # 注册REGEXP
        conn.create_function('REGEXP', 2, regexp)
        cursor = conn.cursor()
        query = "SELECT {} FROM {}".format(k, table)
        if condition:
            query += " WHERE {}".format(condition)
        logger.debug("The DB Query: {}".format(query), origin="db", verify=KB["DEBUG"])
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
    dbpath = os.path.join(root, 'data', 'z0scan.db')
    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()
    # 载入表、字段
    cursor.execute('CREATE TABLE IF NOT EXISTS WAFHISTORY(HOSTNAME TEXT, STATE BOOL)')
    cursor.execute('CREATE TABLE IF NOT EXISTS SCANNED(HOSTNAME TEXT, URL TEXT)')
    conn.commit()
    conn.close()
    return True