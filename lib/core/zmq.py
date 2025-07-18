#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/5

from lib.core.data import conf, KB
from lib.core.log import logger
import threading, time, sys
from typing import Optional

try:
    import zmq
    ZMQ_AVAILABLE = True
except ImportError:
    ZMQ_AVAILABLE = False
    import socket

class BackgroundZeroMQServer:
    def __init__(self, port: int = 9331):
        self.port = port
        self.ctx: Optional[zmq.Context] = None
        self.socket = None
        self.running = False
        self.server_thread: Optional[threading.Thread] = None
        self.use_zmq = ZMQ_AVAILABLE

    def _server_loop(self):
        """服务端内部循环"""
        if self.use_zmq:
            self._zmq_server_loop()
        else:
            self._socket_server_loop()

    def _zmq_server_loop(self):
        """ZeroMQ服务端循环"""
        self.ctx = zmq.Context()
        self.socket = self.ctx.socket(zmq.REP)
        self.socket.bind(f"tcp://*:{self.port}")
        logger.info(f"ZeroMQ server started on port {self.port}")
        
        while self.running:
            try:
                msg = self.socket.recv_string()
                logger.debug(f"Received message: {msg}", level=1)
                r = Command().exec_command(msg)
                self.socket.send_string(r)
            except zmq.ZMQError as e:
                logger.error(f"Server error: {e}")
                break

    def _socket_server_loop(self):
        """Socket服务端循环"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('localhost', self.port))
        self.socket.listen(1)
        logger.warning(f"ZeroMQ server init fail, Socket server started on port {self.port}")
        logger.info(f"You can replace Socket with ZeroMQ by installing ZeroMQ")
        
        while self.running:
            try:
                conn, addr = self.socket.accept()
                with conn:
                    logger.debug(f"Connected by {addr}", level=1)
                    data = conn.recv(1024)
                    if not data:
                        continue
                    msg = data.decode('utf-8')
                    logger.debug(f"Received message: {msg}", level=1)
                    r = Command().exec_command(msg)
                    conn.sendall(r.encode('utf-8'))
            except Exception as e:
                if self.running:
                    logger.error(f"Server error: {e}")
                break

    def start(self):
        """启动服务端（非阻塞）"""
        if self.running:
            logger.warning("Server is already running")
            return

        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        return self  # 返回实例以便链式调用

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.use_zmq:
            if self.socket:
                self.socket.close()
            if self.ctx:
                self.ctx.term()
        else:
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.socket.close()
        logger.info(f"Server stopped ({'ZeroMQ' if self.use_zmq else 'Socket'})")

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """支持上下文管理器"""
        self.stop()

class ZeroMQClient:
    def __init__(self, host: str = "localhost", port: int = 9331, timeout: int = 3000):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_zmq = ZMQ_AVAILABLE
        self.socket = None
        
        if self.use_zmq:
            self._init_zmq_client()
        else:
            self._init_socket_client()

    def _init_zmq_client(self):
        """初始化ZeroMQ客户端"""
        self.ctx = zmq.Context()
        self.socket = self.ctx.socket(zmq.DEALER)
        self.socket.setsockopt(zmq.LINGER, 0)
        self.socket.setsockopt(zmq.RCVTIMEO, self.timeout)  # 设置接收超时
        self.socket.connect(f"tcp://{self.host}:{self.port}")
        logger.info(f"ZeroMQ client connected to server at {self.host}:{self.port}")

    def _init_socket_client(self):
        """初始化Socket客户端"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout / 1000.0)  # 转换为秒
        try:
            self.socket.connect((self.host, self.port))
            logger.info(f"Socket client connected to server at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Socket connection error: {e}")
            sys.exit()
            self.socket = None

    def send_message(self, message: str) -> Optional[str]:
        if self.use_zmq:
            return self._zmq_send_message(message)
        else:
            return self._socket_send_message(message)

    def _zmq_send_message(self, message: str) -> Optional[str]:
        """ZeroMQ发送消息实现"""
        try:
            self.socket.send_string(message)
            return self.socket.recv_string()
        except zmq.Again:
            logger.warning(f"Timeout after {self.timeout}ms while waiting for reply")
            return None
        except zmq.ZMQError as e:
            logger.error(f"ZMQ error occurred: {str(e)}")
            return None

    def _socket_send_message(self, message: str) -> Optional[str]:
        """Socket发送消息实现"""
        if not self.socket:
            logger.error("Socket not initialized")
            return None
            
        try:
            self.socket.sendall(message.encode('utf-8'))
            data = self.socket.recv(1024)
            return data.decode('utf-8') if data else None
        except socket.timeout:
            logger.warning(f"Timeout after {self.timeout}ms while waiting for reply")
            return None
        except Exception as e:
            logger.error(f"Socket error occurred: {str(e)}")
            self._init_socket_client()  # 尝试重新连接
            return None

    def close(self):
        if self.use_zmq:
            try:
                self.socket.close()
                self.ctx.term()
            except zmq.ZMQError as e:
                logger.error(f"Error closing ZeroMQ connection: {str(e)}")
        else:
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.socket.close()
                logger.info("Socket connection closed")

class Command:
    def parse_command(self, input_str):
        parts = input_str.strip().split()
        if not parts:
            return None, None
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        return command, args
    
    def exec_command(self, msg):
        cmd, args = self.parse_command(msg)
        if cmd == "help":
            help_text = """Available Commands:
    help      - Show this help message
    pause     - Pause current operation
    set       - Set parameter (format: set key=value)
        Allowed parameters: level, timeout, retry, risk
    env       - Show current configuration
    status    - Scan status
    
    Examples:
    set level=3
    pause"""
            return help_text
            
        elif cmd == "pause":
            KB.pause = True
            return "Operation paused"
            
        elif cmd == "set":
            if len(args) < 1:
                return "Error: Parameter required (format: set key=value)"
                
            try:
                key, value = args[0].split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key not in ["level", "timeout", "retry", "risk"]:
                    return f"Error: Not allowed to set parameter '{key}'"
                    
                if key == "risk" and value.startswith('[') and value.endswith(']'):
                    try:
                        # Convert string list to actual list of floats
                        value = [int(x.strip()) for x in value[1:-1].split(',')]
                    except ValueError as e:
                        return f"Error: Invalid risk list values ({str(e)})"
                if key in ["level", "retry"]:
                    value = int(value)
                elif key in ["timeout"]:
                    value = float(value)
                    
                setattr(conf, key, value)
                return f"Parameter set: {key} => {value}"
                
            except ValueError as e:
                return f"Error: Invalid parameter value ({str(e)})"
                
        elif cmd == "env":
            env_info = "\n".join(
                f"{k}: {getattr(conf, k, 'N/A')}"
                for k in ["level", "timeout", "retry", "risk"]
            )
            return f"Current Configuration:\n{env_info}"
        
        elif cmd == "status":
            status_info = f'{KB.output.count():d} SUCCESS | {KB.running:d} RUNNING | {KB.task_queue.qsize():d} REMAIN | {KB.finished:d} SCANNED IN {time.time()-KB.start_time:.2f}s'
            return f"Scan Status:\n{status_info}"
            
        else:
            return f"Error: Unknown command '{cmd}'. Type 'help' for available commands"