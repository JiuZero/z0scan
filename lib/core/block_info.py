#!/usr/bin/env python3
# caicai 2020-02-14

from lib.core.data import conf
from lib.core.log import logger
from lib.core.db import selectdb, insertdb, updatedb

class block_count():
    def __init__(self, host, port):
        self.host_port = "{}_{}".format(host, port)

    def push_result_status(self, status):
        '''
        status  01000
        0:状态正常
        1:状态异常
        '''
        try:
            # 检查记录是否存在
            result = selectdb("block_count", "count", where="id=?", where_values=[self.host_port])
            
            if result is False or result is None:
                # 记录不存在，创建新记录
                insertdb("block_count", {"id": self.host_port, "count": str(status)})
                origin = ""
            else:
                # 记录存在，获取当前计数
                origin = result[0] if result else ""
            
            # 构建新的计数字符串
            new_count = origin + str(status)
            
            # 更新记录（使用UPDATE而不是INSERT）
            if result is False or result is None:
                insertdb("block_count", {"id": self.host_port, "count": new_count})
            else:
                # 使用UPDATE更新现有记录
                updatedb("block_count", "count=?", "id=?", [new_count, self.host_port])
            
            # 检查是否需要阻塞
            if len(new_count) >= 10:  # 至少要有10个状态才能判断
                recent_status = new_count[-10:]  # 最近10个状态
                if recent_status.count("0") >= int(conf.block_count):
                    insertdb("block_host", {"id": self.host_port})
                    logger.warning("{} blocked, never test it.".format(self.host_port))
            
            return True
            
        except Exception as e:
            logger.error(f"Error in push_result_status: {e}", origin="block_count")
            return False

    def is_block(self):
        try:
            result = selectdb("block_host", "id", where="id=?", where_values=[self.host_port])
            return result is not None and result is not False
        except Exception as e:
            logger.error(f"Error in is_block: {e}", origin="block_count")
            return False

    def block_it(self):
        try:
            insertdb("block_host", {"id": self.host_port})
            logger.info("{} manually blocked.".format(self.host_port))
            return True
        except Exception as e:
            logger.error(f"Error in block_it: {e}", origin="block_count")
            return False
