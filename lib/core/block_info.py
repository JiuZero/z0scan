#!/usr/bin/env python3
# caicai 2020-02-14

from lib.core.data import conf
from lib.core.log import logger
from lib.core.db import selectdb, insertdb

class block_count():
    def __init__(self, host, port):
        self.host_port = "{}_{}".format(host, port)

    def push_result_status(self, status):
        '''
        status  01000
        0:状态正常
        1:状态异常
        '''
        if not selectdb("block_count", "id", where=f"'id'='{self.host_port}'"):
            insertdb("block_count", {"id": self.host_port, "count": ""})
        origin = str(selectdb("block_count", "count", where=f"id='{self.host_port}'"))
        new = origin + str(status)
        insertdb("block_count", {"id": self.host_port, "count": new})
        if new[-10:].count("0") >= int(conf.block_count):
            insertdb("block_host", {"id": self.host_port})
            logger.warning("{} blocked, never test it.".format(self.host_port))
        return

    def is_block(self):
        if selectdb("block_host", "id", where=f"'id'='{self.host_port}'"):
            return True
        else:
            return False

    def block_it(self):
        insertdb("block_host", {"id": self.host_port})
