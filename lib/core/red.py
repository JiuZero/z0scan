#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/10

import sys, redis
from lib.core.data import conn, conf
from lib.core.log import logger

def redis_conn():
    arg_redis = conf.get("redis_server") or conf.get("redis_client")
    if arg_redis:
        if "@" in arg_redis:
            pwd, ipport = arg_redis.split("@", 1)
            if not pwd:
                pwd = None
            if ":" in ipport and ipport.count(".") >= 2:
                ip, port, db = ipport.split(":", 2)
            else:
                ip = ipport
                port = 6379
                db = 0
            logger.debug("Redis connection args: pwd:{}-ip:{}-port:{}-db:{}".format(pwd, ip, port, db))
            conn.redis = redis.ConnectionPool(max_connections=300, host=ip, password=pwd, port=int(port), db=int(db))

def gredis():
    return redis.StrictRedis(connection_pool=conn.redis)
    
def set_conn():
    try:
        redis_conn()
        red = gredis()
        if not red.ping():
            error_msg = "Redis connect fail. Exiting..."
            logger.warning(error_msg)
            sys.exit()
        else:
            logger.info("Connecting to Redis. OK")
    except Exception as ex:
        error_msg = "Get error when connecting to redis. Please use --redis pass@host:port:db, if pass is none ,like --redis @host:port:db. Error: {}".format(ex)
        logger.warning(error_msg)
        sys.exit()
    # TODO 其他连接方式


def cleanred():
    # red = redis.StrictRedis(connection_pool=conn.redis)
    red = gredis()
    red.flushall()