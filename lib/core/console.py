#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/8/10

from lib.core.data import conf, KB, path
from lib.core.log import logger
import threading, time, sys, os
from typing import Optional
import socket
from lib.core.common import ltrim
from lib.core.exection import PluginCheckError
from lib.core.loader import load_file_to_module

class BackgroundServer:
    def __init__(self, port: int = 9090):
        self.port = port
        self.socket = None
        self.running = False
        self.server_thread: Optional[threading.Thread] = None

    def _server_loop(self):
        """服务端内部循环"""
        self._socket_server_loop()

    def _socket_server_loop(self):
        """Socket服务端循环"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('localhost', self.port))
        self.socket.listen(1)
        logger.info(f"Socket server started on port {self.port}")
        
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
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.socket.close()
        logger.info(f"Server stopped Socket")

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """支持上下文管理器"""
        self.stop()

class Client:
    def __init__(self, host: str = "localhost", port: int = 9331, timeout: int = 3000):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        
        self._init_socket_client()

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
        return self._socket_send_message(message)

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
    enable      - Load new plugins
    disable   - Disable plugins that be enableed
    
    Examples:
    set level=3
    enable sqli-error,sqli-bool
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
                if key not in ["level", "timeout", "retry", "disable"]:
                    return f"Error: Not allowed to set parameter '{key}'"
                if key in ["level", "retry"]:
                    value = int(value)
                elif key in ["timeout"]:
                    value = float(value)
                if key in ["disable"]:
                    conf.disable += value
                else:
                    setattr(conf, key, value)
                return f"Parameter set: {key} => {value}"
            except ValueError as e:
                return f"Error: Invalid parameter value ({str(e)})"
        elif cmd == "enable":
            enable_new_plugins(args)
        elif cmd == "disable":
            disable_plugins(args)
        elif cmd == "env":
            env_info = "\n".join(
                f"{k}: {getattr(conf, k, 'N/A')}"
                for k in ["level", "timeout", "retry", "risk", "disable"]
            )
            return f"Current Configuration:\n{env_info}"
        elif cmd == "status":
            status_info = f'{KB.output.count():d} SUCCESS | {KB.running:d} RUNNING | {KB.task_queue.qsize():d} REMAIN | {KB.finished:d} SCANNED IN {time.time()-KB.start_time:.2f}s'
            return f"Scan Status:\n{status_info}"
        else:
            return f"Error: Unknown command '{cmd}'. Type 'help' for available commands"


def disable_plugins(disable_list: list):
    for _dir in ["PerPage", "PerDir", "PerDomain"]:
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            dis_list = ""
            for _ in files:
                filename = os.path.join(root, _)
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    if not mod.name in disable_list:
                        continue
                    if not mod.name in KB["registered"].keys:
                        logger.warning(f"Plugin {mod.name} hadn't been loaded. Skip.")
                        continue
                    plugin = os.path.splitext(_)[0]
                    dis_list += f" {mod.name}"
                    del KB["registered"][plugin]
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
        logger.info(f'Disable plugins:{dis_list}.')

def enable_new_plugins(enable_list: list):
    for _dir in ["PerPage", "PerDir", "PerDomain"]:
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            new_add = ""
            for _ in files:
                q = os.path.splitext(_)[0]
                filename = os.path.join(root, _)
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    if not mod.name in KB["registered"].keys:
                        logger.warning(f"Plugin {mod.name} had been enableed. Skip.")
                        continue
                    if not mod.name in enable_list:
                        continue
                    new_add += f" {mod.name}"
                    plugin = os.path.splitext(_)[0]
                    plugin_type = os.path.split(root)[1]
                    relative_path = ltrim(filename, path.root)
                    if getattr(mod, 'type', None) is None:
                        setattr(mod, 'type', plugin_type)
                    if getattr(mod, 'path', None) is None:
                        setattr(mod, 'path', relative_path)
                    KB["registered"][plugin] = mod
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
        logger.info(f'New enable plugins:{new_add}.')