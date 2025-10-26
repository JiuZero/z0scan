#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/7

import threading
import re
import socket
import time
from lib.core.log import logger
from lib.core.data import KB, conf
from lib.controller.controller import task_push_for_portscan

class ScanPort:
    def __init__(self, ipaddr):
        self.ipaddr = ipaddr
        self.threads = []  # 存储线程引用，用于等待所有线程完成

    def socket_scan(self, task):
        PROBE = {'GET / HTTP/1.0\r\n\r\n'}  # 端口探测请求
        response = ''
        ip = self.ipaddr
        plugin_name, ports, fingers = task
        
        try:
            for port in ports:
                # 为每个端口创建独立socket（避免资源复用导致的阻塞）
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # 仅保留单个端口的操作超时（2秒），防止单端口阻塞
                sock.settimeout(3.0)
                
                try:
                    # 尝试建立TCP连接（非阻塞式，受settlement控制）
                    result = sock.connect_ex((ip, int(port)))
                    
                    # 连接成功（3次握手完成）
                    if result == 0:
                        try:
                            # 发送探测包获取服务响应
                            for probe in PROBE:
                                sock.sendall(probe.encode('utf-8'))
                                # 接收服务响应（超时由socket.settimeout控制）
                                response = sock.recv(256).decode('utf-8', 'ignore')
                                
                                if response:
                                    # 过滤502网关错误场景
                                    if re.search(r'<title>502 Bad Gateway', response, re.IGNORECASE):
                                        return
                                        
                                    logger.debug(f"{ip}:{port} OPEN", origin="portscan")
                                    # 匹配服务指纹，加载对应插件
                                    if fingers:
                                        for pattern in fingers:
                                            # 统一指纹格式（处理bytes/str混合场景）
                                            pattern_str = pattern.decode('utf-8') if isinstance(pattern, bytes) else str(pattern)
                                            pattern_parts = pattern_str.split('|')
                                            
                                            for p in pattern_parts:
                                                if re.search(p, response, re.IGNORECASE):
                                                    logger.info(f"Load plugin '{plugin_name}' on {ip}:{port}", origin="portscan")
                                                    task_push_for_portscan(plugin_name, host=f"{ip}:{port}", sockrecv=response)
                                                    break  # 匹配到一个指纹即可，避免重复加载
                                    # 无指纹时直接加载插件
                                    else:
                                        logger.info(f"Load plugin '{plugin_name}' on {ip}:{port} (no fingerprint)", origin="portscan")
                                        task_push_for_portscan(plugin_name, host=f"{ip}:{port}", sockrecv=response)
                                        
                        except socket.timeout:
                            logger.debug(f"{ip}:{port} response timeout (no service data)", origin="portscan")
                            continue
                        finally:
                            # 强制关闭socket，释放资源（避免句柄泄漏）
                            try:
                                sock.close()
                            except Exception as close_e:
                                logger.debug(f"Close socket error: {str(close_e)}", origin="portscan")
                                
                except socket.timeout:
                    logger.debug(f"{ip}:{port} connection timeout (no TCP handshake)", origin="portscan")
                    continue
                except (ConnectionResetError, OSError) as conn_e:
                    logger.debug(f"{ip}:{port} connection failed: {str(conn_e)}", origin="portscan")
                    continue
                finally:
                    # 双重保障：确保socket被关闭（即使前面出现异常）
                    try:
                        if not sock._closed:
                            sock.close()
                    except:
                        pass
                        
        except Exception as thread_e:
            logger.error(f"Scan thread error: {str(thread_e)}", origin="portscan")
            
    def run(self):
        try:
            # 解析主机名（如果输入的是域名而非IP）
            if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', self.ipaddr):
                logger.debug(f"Resolving hostname: {self.ipaddr}", origin="portscan")
                self.ipaddr = socket.gethostbyname(self.ipaddr)
                logger.debug(f"Resolved to IP: {self.ipaddr}", origin="portscan")
            
            # 加载端口扫描任务（从KB中获取插件-端口-指纹映射）
            tasks = []
            for poc_name, info in KB["portscan"].items():
                ports, fingers = info
                # 过滤无效端口（1-65535）
                valid_ports = [p for p in ports if 1 <= int(p) <= 65535]
                if valid_ports:
                    tasks.append((poc_name, valid_ports, fingers))
            
            if not tasks:
                return
            
            # 启动线程执行扫描任务
            self.threads = []
            for task in tasks:
                thread = threading.Thread(target=self.socket_scan, args=(task,))
                thread.daemon = False  # 非守护线程，确保扫描完成前主程序不退出
                self.threads.append(thread)
                thread.start()
                logger.debug(f"Started thread for plugin: {task[0]}", origin="portscan")
            
            # 等待所有扫描线程完成（确保所有端口扫描结束）
            for thread in self.threads:
                thread.join()  # 阻塞等待单个线程完成，无超时
                
            logger.debug(f"All tasks completed for {self.ipaddr}", origin="portscan")
            
        except socket.gaierror:
            logger.error(f"Failed to resolve hostname: {self.ipaddr}", origin="portscan")
        except Exception as run_e:
            logger.error(f"Main scan error: {str(run_e)}", origin="portscan")