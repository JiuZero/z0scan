#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/2/23

import sqlite3, os, sys, re
import threading
from lib.core.log import logger
from typing import Union, List, Dict, Any
from contextlib import contextmanager

# 全局数据库锁
db_lock = threading.Lock()

def regexp(pattern, string):
    return re.match(pattern, string) is not None

@contextmanager
def db_connection():
    """数据库连接上下文管理器，确保连接在使用后正确关闭"""
    conn = None
    try:
        conn = sqlite3.connect(dbpath)
        yield conn
    finally:
        if conn:
            conn.close()

def insertdb(table: str, columns_values: dict):
    try:
        columns = ""
        placeholders = ""
        values = []
        for column, value in columns_values.items():
            columns += str(column) + ","
            placeholders += "?,"
            values.append(str(value))
        columns = columns.rstrip(",")
        placeholders = placeholders.rstrip(",")
        
        query = 'INSERT INTO {} ({}) VALUES({})'.format(table, columns, placeholders)
        logger.debug("The DB Query: {}".format(query), origin="db", level=3)
        
        with db_lock:  # 使用锁确保线程安全
            with db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, values)
                conn.commit()
        return True
    except Exception as e:
        logger.error(e, origin="db")
        return False

def selectdb(table: str, columns:str, where=None, where_values=None):
    try:
        query = "SELECT {} FROM {}".format(columns, table)
        if where:
            query += " WHERE {}".format(where)
        logger.debug("The DB Query: {}".format(query), origin="db", level=3)
        
        with db_lock:  # 使用锁确保线程安全
            with db_connection() as conn:
                cursor = conn.cursor()
                if where and where_values:
                    cursor.execute(query, where_values)
                else:
                    cursor.execute(query)
                result = cursor.fetchone()
        return result
    except sqlite3.OperationalError as e:
        logger.warning(e, origin="db")
        return False
    except Exception as e:
        logger.error(e, origin="db")
        return False
    
def initdb(root):
    global dbpath
    dbpath = os.path.join(root, 'data', 'z0scan.db')
    
    with db_lock:  # 使用锁确保线程安全
        with db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('DELETE FROM block_count')
                cursor.execute('DELETE FROM block_id')
            except:
                pass
            # 域名信息记录
            # port: |80|443|
            # fingerprint: |os=["LINUX"]|webserver=["NGINX"]|programing=["PHP"]|
            cursor.execute('CREATE TABLE IF NOT EXISTS info(hostname TEXT, waf TEXT, port TEXT, fingerprint TEXT)')
            cursor.execute('CREATE TABLE IF NOT EXISTS block_count(id TEXT, count TEXT)')
            cursor.execute('CREATE TABLE IF NOT EXISTS block_host(id TEXT)')
            # 缓存记录（记录每次项目启动后扫描过的URL及关联信息）
            try:
                cursor.execute('DELETE FROM cache')
            except:
                pass
            try:
                cursor.execute('CREATE TABLE IF NOT EXISTS cache(hostname TEXT, requestsRaw TEXT)')
                conn.commit()
                return True
            except Exception as e:
                logger.error(e, origin="db")
                return False

def execute_sqlite_command(command: str) -> Union[List[Dict[str, Any]], str]:
    try:
        with db_lock:  # 使用锁确保线程安全
            with db_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(command)
                
                if command.strip().upper().startswith(('SELECT', 'PRAGMA')):
                    # 查询命令，返回结果集
                    results = [dict(row) for row in cursor.fetchall()]
                    return results
                else:
                    # 非查询命令，提交变更并返回影响行数
                    conn.commit()
                    return f"Command executed successfully. Rows affected: {cursor.rowcount}"
    except sqlite3.Error as e:
        return f"SQLite error occurred: {str(e)}"
    except Exception as e:
        return f"An error occurred: {str(e)}"