#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Web 工作模式（http.server）：内置 HTTP 服务与前端控制台
# 要求：访问必须携带 ?{随机6位}={随机6位} 查询参数
# 本版新增：SSE 实时日志流 /api/log/stream

import os
import sys
import time
import json
import threading
import secrets
import string
import queue
import collections
from typing import Optional
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from lib.core.data import conf, KB, path
from lib.core.log import logger, colors
from lib.core.common import ltrim
from lib.core.exection import PluginCheckError
from lib.core.loader import load_file_to_module


class Command:
    def parse_command(self, input_str: str):
        parts = input_str.strip().split()
        if not parts:
            return None, None
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        return command, args

    def exec_command(self, msg: str) -> str:
        cmd, args = self.parse_command(msg)
        if not cmd:
            return "Error: Empty command"

        if cmd == "help":
            help_text = """Available Commands:
  help        - Show this help message
  pause       - Pause current operation
  set         - Set parameter (format: set key=value)
                Allowed parameters: level, timeout, retry, risk, disable
  env         - Show current configuration
  status      - Scan status
  enable      - Load new plugins
  disable     - Disable plugins that be enabled

Examples:
  set level=3
  enable sqli-error,sqli-bool
  pause"""
            return help_text

        if cmd == "pause":
            try:
                KB.pause = True
            except Exception:
                pass
            return "Operation paused"

        if cmd == "set":
            if len(args) < 1:
                return "Error: Parameter required (format: set key=value)"
            try:
                key, value = args[0].split("=", 1)
                key = key.strip()
                value = value.strip()
                if key not in ["level", "timeout", "retry", "risk", "disable"]:
                    return f"Error: Not allowed to set parameter '{key}'"
                if key in ["level", "retry"]:
                    value = int(value)
                elif key == "timeout":
                    value = float(value)
                if key == "disable":
                    # 允许追加禁用列表（逗号分隔）
                    exist = getattr(conf, "disable", [])
                    if isinstance(value, str):
                        items = [_.strip() for _ in value.split(",") if _.strip()]
                    else:
                        items = list(value)
                    if not isinstance(exist, list):
                        exist = []
                    setattr(conf, "disable", list({*exist, *items}))
                else:
                    setattr(conf, key, value)
                return f"Parameter set: {key} => {value}"
            except ValueError as e:
                return f"Error: Invalid parameter value ({str(e)})"

        if cmd == "enable":
            enable_list = []
            if args:
                enable_list = args[0].split(",") if isinstance(args[0], str) else list(args)
                enable_list = [_.strip() for _ in enable_list if _.strip()]
            enable_new_plugins(enable_list)
            return f"Enable request for: {', '.join(enable_list) if enable_list else '(none)'}"

        if cmd == "disable":
            disable_list = []
            if args:
                disable_list = args[0].split(",") if isinstance(args[0], str) else list(args)
                disable_list = [_.strip() for _ in disable_list if _.strip()]
            disable_plugins(disable_list)
            return f"Disable request for: {', '.join(disable_list) if disable_list else '(none)'}"

        if cmd == "env":
            keys = ["level", "timeout", "retry", "risk", "disable"]
            env_info = "\n".join(f"{k}: {getattr(conf, k, 'N/A')}" for k in keys)
            return f"Current Configuration:\n{env_info}"

        if cmd == "status":
            try:
                count = KB.output.count() if hasattr(KB, "output") and callable(getattr(KB.output, "count", None)) else 0
            except Exception:
                count = 0
            try:
                running = getattr(KB, "running", 0)
            except Exception:
                running = 0
            try:
                remain = KB.task_queue.qsize() if hasattr(KB, "task_queue") and callable(getattr(KB.task_queue, "qsize", None)) else 0
            except Exception:
                remain = 0
            try:
                finished = getattr(KB, "finished", 0)
            except Exception:
                finished = 0
            try:
                elapsed = time.time() - getattr(KB, "start_time", time.time())
            except Exception:
                elapsed = 0.0
            return f"Scan Status:\n{count:d} SUCCESS | {running:d} RUNNING | {remain:d} REMAIN | {finished:d} SCANNED IN {elapsed:.2f}s"

        return f"Error: Unknown command '{cmd}'. Type 'help' for available commands"


def disable_plugins(disable_list: list):
    if not disable_list:
        return
    for _dir in ["PerPage", "PerDir", "PerDomain", "PerHost"]:
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            dis_list = ""
            for _ in files:
                filename = os.path.join(root, _)
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    if mod.name not in disable_list:
                        continue
                    if not isinstance(KB, dict) or "registered" not in KB or mod.name not in KB.get("registered", {}):
                        # 以插件文件名索引
                        plugin = os.path.splitext(_)[0]
                        if plugin in KB.get("registered", {}):
                            del KB["registered"][plugin]
                            dis_list += f" {mod.name}"
                        else:
                            logger.warning(f"Plugin {mod.name} hadn't been loaded. Skip.")
                        continue
                    plugin = os.path.splitext(_)[0]
                    dis_list += f" {mod.name}"
                    if plugin in KB["registered"]:
                        del KB["registered"][plugin]
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
            if dis_list:
                logger.info(f'Disable plugins:{dis_list}.')


def enable_new_plugins(enable_list: list):
    if not enable_list:
        return
    for _dir in ["PerPage", "PerDir", "PerDomain", "PerHost"]:
        for root, dirs, files in os.walk(os.path.join(path.scanners, _dir)):
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            new_add = ""
            for _ in files:
                filename = os.path.join(root, _)
                q = os.path.splitext(_)[0]
                mod = load_file_to_module(filename)
                try:
                    mod = mod.Z0SCAN()
                    mod.checkImplemennted()
                    if hasattr(mod, "name") and mod.name not in enable_list:
                        continue
                    # 已启用则跳过
                    if isinstance(KB, dict) and "registered" in KB and (q in KB["registered"]):
                        continue
                    plugin = q
                    plugin_type = os.path.split(root)[1]
                    relative_path = ltrim(filename, path.root)
                    if getattr(mod, "type", None) is None:
                        setattr(mod, "type", plugin_type)
                    if getattr(mod, "path", None) is None:
                        setattr(mod, "path", relative_path)
                    if "registered" not in KB:
                        KB["registered"] = {}
                    KB["registered"][plugin] = mod
                    if hasattr(mod, "name"):
                        new_add += f" {mod.name}"
                except PluginCheckError as e:
                    logger.error('Not "{}" attribute in the plugin: {}'.format(e, filename))
                except AttributeError as e:
                    logger.error('Filename: {} not class "{}", Reason: {}'.format(filename, 'Z0SCAN', e))
                    raise
            if new_add:
                logger.info(f'New enabled plugins:{new_add}.')


# 线程化 HTTPServer
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# UI 模板：增加“实时日志(SSE)”区域
DASHBOARD_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Z0SCAN Web Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{
  --bg1:#0b0f15; --bg2:#0b1220; --card:#101826; --border:#1f2a3a; --muted:#9aa7b2; --fg:#e6edf3; --accent:#7c9cff; --accent2:#22d3ee; --danger:#f87171;
}
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial; margin:0; color:var(--fg); background: radial-gradient(1200px 600px at 20% -20%, rgba(124,156,255,.08), transparent), linear-gradient(180deg, var(--bg1), var(--bg2));}
header{position:sticky;top:0;z-index:50; padding:14px 20px; background:rgba(16,24,38,.8); backdrop-filter:saturate(140%) blur(10px); border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center;}
.brand{display:flex; align-items:center; gap:10px;}
.logo{width:10px;height:10px;border-radius:50%; background: conic-gradient(from 0deg, var(--accent), var(--accent2)); box-shadow:0 0 20px rgba(34,211,238,.6);}
.badge{ background:#0d1523; border:1px solid var(--border); padding:4px 8px; border-radius:999px; color:#9ca3af;}
.container{ padding:18px 20px; display:grid; grid-template-columns: 1.1fr .9fr; gap:16px; }
.card{ background:linear-gradient(180deg,#0d1523, #0c1320); border:1px solid var(--border); border-radius:14px; padding:14px; box-shadow:0 10px 30px rgba(3,8,20,.35), inset 0 1px 0 rgba(255,255,255,.03);}
.card h3{ margin:0 0 10px 0; font-size:16px; display:flex; align-items:center; gap:8px;}
.card h3::after{content:''; flex:1; height:1px; background:linear-gradient(90deg, rgba(124,156,255,.4), rgba(34,211,238,.1)); margin-left:8px;}
.controls{ display:flex; flex-wrap:wrap; gap:8px; }
button,input,select{ background:#0b1220; color:#cbd5e1; border:1px solid #243244; border-radius:10px; padding:8px 10px; transition:all .2s ease;}
button{ cursor:pointer; }
button:hover{ transform: translateY(-1px); box-shadow:0 6px 14px rgba(124,156,255,.18); border-color:var(--accent); }
pre{ white-space:pre-wrap; word-break:break-word; background:#07101c; padding:12px; border-radius:10px; border:1px solid #223049; max-height:360px; overflow:auto; }
footer{ padding:12px 20px; color:#94a3b8; opacity:.9;}
.kv{ display:flex; gap:8px; align-items:center; }
.kv input{ width: 120px; }
.stat{display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px; background:#0d1523; border:1px solid var(--border);}
.stat b{color:var(--accent2)}
hr.sep{border:none; height:1px; background:linear-gradient(90deg, transparent, #233046, transparent); margin:8px 0;}
.log{ max-height:280px; }
</style>
</head>
<body>
<header>
  <div class="brand"><span class="logo"></span><strong>Z0SCAN Web Console</strong> <span class="badge">已授权会话</span></div>
  <div class="controls">
    <button onclick="api('help')"><i class="fa fa-circle-question"></i> 帮助</button>
    <button onclick="api('env')"><i class="fa fa-gear"></i> 环境</button>
    <button onclick="api('status').then(updateStat)"><i class="fa fa-gauge"></i> 状态</button>
    <button onclick="api('pause')"><i class="fa fa-pause"></i> 暂停</button>
  </div>
</header>
<div class="container">
  <div class="card">
    <h3><i class="fa fa-sliders"></i> 快速设置</h3>
    <div class="controls">
      <div class="kv">
        <label>level=</label><input id="level" type="number" min="0" step="1" value="1"/>
        <button onclick="setParam('level')">设置</button>
      </div>
      <div class="kv">
        <label>timeout=</label><input id="timeout" type="number" min="0" step="0.1" value="5"/>
        <button onclick="setParam('timeout')">设置</button>
      </div>
      <div class="kv">
        <label>retry=</label><input id="retry" type="number" min="0" step="1" value="1"/>
        <button onclick="setParam('retry')">设置</button>
      </div>
    </div>
    <hr class="sep"/>
    <div class="controls">
      <input id="enableList" placeholder="启用插件名,逗号分隔"/>
      <button onclick="runEnable()">启用</button>
      <input id="disableList" placeholder="禁用插件名,逗号分隔"/>
      <button onclick="runDisable()">禁用</button>
    </div>
  </div>
  <div class="card">
    <h3><i class="fa fa-terminal"></i> 输出</h3>
    <pre id="out"></pre>
    <div class="stat" id="stat"></div>
  </div>

  <div class="card" style="grid-column: 1 / span 2;">
    <h3><i class="fa fa-file-lines"></i> 实时日志</h3>
    <pre id="logs" class="log"></pre>
  </div>

  <div class="card" style="grid-column: 1 / span 2;">
    <h3><i class="fa fa-keyboard"></i> 自定义命令</h3>
    <div class="controls">
      <input id="cmd" placeholder="例如: set level=3 或 status 或 help" style="flex:1;"/>
      <button onclick="runCmd()">执行</button>
    </div>
  </div>
</div>
<footer>© z0scan</footer>

<script>
function withQS(url){ const qs = window.location.search || ''; return url + (qs || ''); }

async function api(cmd, args=[]){
  const res = await fetch(withQS('/api/command'), {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ cmd, args })
  });
  const data = await res.json();
  const text = data.ok ? data.result : ('Error: ' + data.error);
  print(text);
  return text;
}
function print(text){ document.getElementById('out').textContent = (text || '').toString(); }
function setParam(key){
  const val = document.getElementById(key).value;
  api('set', [key + '=' + val]).then(updateStat);
}
function runEnable(){
  const v = document.getElementById('enableList').value.trim();
  if(!v) return;
  api('enable', [v]).then(updateStat);
}
function runDisable(){
  const v = document.getElementById('disableList').value.trim();
  if(!v) return;
  api('disable', [v]).then(updateStat);
}
function runCmd(){
  const v = document.getElementById('cmd').value.trim();
  if(!v) return;
  const parts = v.split(' ');
  api(parts[0], parts.slice(1)).then(updateStat);
}
function updateStat(text){
  if(!text){ return; }
  const m = /Scan Status:\\n(.+)/.exec(text) || /(.+SUCCESS.+RUNNING.+REMAIN.+SCANNED.+)/.exec(text);
  const el = document.getElementById('stat');
  el.textContent = m ? m[1] : '';
}

// 实时日志（SSE）
let es;
function startLogStream(){
  try{
    if (es) es.close();
    es = new EventSource(withQS('/api/log/stream'));
    const logs = document.getElementById('logs');
    es.onmessage = (ev) => {
      const line = ev.data || '';
      if (!line) return;
      let html = line;
      if (line.includes('[ERROR]')) html = `<span style="color:#f87171;">${line}</span>`;
      else if (line.includes('[WARNING]')) html = `<span style="color:#f59e0b;">${line}</span>`;
      else if (line.includes('[SUCCESS]')) html = `<span style="color:#22d3ee;">${line}</span>`;
      else if (line.includes('[INFO]')) html = `<span style="color:#7c9cff;">${line}</span>`;
      logs.innerHTML += html + '\\n';
      logs.scrollTop = logs.scrollHeight;
    };
  }catch(e){
    console.error('日志流启动失败:', e);
  }
}

setTimeout(()=>api('status').then(updateStat), 400);
startLogStream();
</script>
</body>
</html>
"""


class _RequestHandler(BaseHTTPRequestHandler):
    server_version = "z0scanWeb/1.2"

    def _set_common_headers(self, status=200, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()

    def _authorize(self, parsed):
        key = getattr(self.server, "query_key", None)
        val = getattr(self.server, "query_val", None)
        if not key or not val:
            return True
        qs = parse_qs(parsed.query)
        return qs.get(key, [None])[0] == val

    def _log_line(self, level: str, message: str):
        # 统一写入 server 的缓冲与队列，带时间戳
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {message}"
        try:
            self.server.log_buffer.append(line)
        except Exception:
            pass
        try:
            self.server.log_queue.put_nowait(line)
        except Exception:
            pass

    def do_OPTIONS(self):
        self._set_common_headers(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        if not self._authorize(parsed):
            self._set_common_headers(403)
            self.wfile.write(json.dumps({"ok": False, "error": "Forbidden: missing/invalid query token"}).encode("utf-8"))
            return

        if parsed.path in ["/", "/index.html"]:
            self._set_common_headers(200, "text/html; charset=utf-8")
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
            return

        if parsed.path == "/api/help":
            result = Command().exec_command("help")
            self._set_common_headers(200)
            self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
            return

        if parsed.path == "/api/env":
            result = Command().exec_command("env")
            self._set_common_headers(200)
            self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
            return

        if parsed.path == "/api/status":
            result = Command().exec_command("status")
            self._set_common_headers(200)
            self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
            return

        if parsed.path == "/api/log/stream":
            # SSE headers
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            # 先推送最近历史
            try:
                for msg in list(self.server.log_buffer)[-200:]:
                    self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                    self.wfile.flush()
            except Exception:
                pass
            # 持续推送新消息，心跳保持
            try:
                while True:
                    try:
                        msg = self.server.log_queue.get(timeout=15)
                        self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # 心跳
                        self.wfile.write(b"data: \n\n")
                        self.wfile.flush()
            except Exception:
                # 客户端断开
                return

        self._set_common_headers(404)
        self.wfile.write(json.dumps({"ok": False, "error": "Not Found"}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self._authorize(parsed):
            self._set_common_headers(403)
            self.wfile.write(json.dumps({"ok": False, "error": "Forbidden: missing/invalid query token"}).encode("utf-8"))
            return

        # 解析 body
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            data = {}
            if body:
                try:
                    data = json.loads(body.decode("utf-8"))
                except Exception:
                    data = parse_qs(body.decode("utf-8"))
        except Exception as e:
            logger.error(f"Bad request body: {e}")
            self._set_common_headers(400)
            self.wfile.write(json.dumps({"ok": False, "error": "Bad Request"}).encode("utf-8"))
            return

        if parsed.path == "/api/command":
            cmd = data.get("cmd")
            args = data.get("args", [])
            if isinstance(args, dict):
                args = [v[0] for v in args.values()]
            if not cmd or not isinstance(cmd, str):
                self._set_common_headers(400)
                self.wfile.write(json.dumps({"ok": False, "error": "cmd required"}).encode("utf-8"))
                return
            try:
                msg = cmd if not args else f"{cmd} " + " ".join(map(str, args))
                result = Command().exec_command(msg)
                self._set_common_headers(200)
                self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
                # 记录日志
                self._log_line("INFO", f"Command '{msg}' executed")
            except Exception as e:
                logger.error(f"/api/command error: {e}")
                self._set_common_headers(500)
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"))
                self._log_line("ERROR", f"Command error: {e}")
            return

        if parsed.path == "/api/pause":
            try:
                result = Command().exec_command("pause")
                self._set_common_headers(200)
                self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
                self._log_line("INFO", "Paused by user")
            except Exception as e:
                logger.error(f"/api/pause error: {e}")
                self._set_common_headers(500)
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"))
                self._log_line("ERROR", f"Pause error: {e}")
            return

        if parsed.path == "/api/set":
            key = data.get("key"); value = data.get("value")
            if not key or value is None:
                self._set_common_headers(400)
                self.wfile.write(json.dumps({"ok": False, "error": "key and value required"}).encode("utf-8"))
                return
            result = Command().exec_command(f"set {key}={value}")
            self._set_common_headers(200)
            self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
            self._log_line("INFO", f"Config updated: {key}={value}")
            return

        if parsed.path == "/api/enable":
            lst = data.get("list") or data.get("plugins") or ""
            arg = ",".join(lst) if isinstance(lst, list) else str(lst)
            result = Command().exec_command(f"enable {arg}") if arg else Command().exec_command("enable")
            self._set_common_headers(200)
            self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
            self._log_line("SUCCESS", f"Plugins enabled: {arg or '(none)'}")
            return

        if parsed.path == "/api/disable":
            lst = data.get("list") or data.get("plugins") or ""
            arg = ",".join(lst) if isinstance(lst, list) else str(lst)
            result = Command().exec_command(f"disable {arg}") if arg else Command().exec_command("disable")
            self._set_common_headers(200)
            self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8"))
            self._log_line("SUCCESS", f"Plugins disabled: {arg or '(none)'}")
            return

        self._set_common_headers(404)
        self.wfile.write(json.dumps({"ok": False, "error": "Not Found"}).encode("utf-8"))

    def log_message(self, format, *args):
        try:
            logger.debug(f"HTTP {self.address_string()} - {format % args}", level=1)
        except Exception:
            pass


class BackgroundServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 9090):
        self.host = host
        self.port = port
        self.httpd: Optional[HTTPServer] = None
        self.running = False
        self.server_thread: Optional[threading.Thread] = None
        # 查询参数令牌（6+6）
        pool = string.ascii_letters + string.digits
        self.query_key = ''.join(secrets.choice(pool) for _ in range(6))
        self.query_val = ''.join(secrets.choice(pool) for _ in range(6))
        # 实时日志设施
        self.log_buffer = collections.deque(maxlen=1000)
        self.log_queue: "queue.Queue[str]" = queue.Queue()

    def _server_loop(self):
        class Handler(_RequestHandler):
            pass
        try:
            self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
            # 传递访问校验与日志设施
            self.httpd.query_key = self.query_key
            self.httpd.query_val = self.query_val
            self.httpd.log_buffer = self.log_buffer
            self.httpd.log_queue = self.log_queue
        except OSError as e:
            logger.error(f"Web server bind error at {self.host}:{self.port} - {e}")
            self.running = False
            return
        logger.info(f"Web server started at {colors.y}http://{self.host}:{self.port}/?{self.query_key}={self.query_val}{colors.e}")
        # 启动提示写入日志
        ts = time.strftime("%H:%M:%S")
        self.log_buffer.append(f"[{ts}] [INFO] 控制台服务已启动，等待事件...")
        try:
            self.httpd.serve_forever()
        except Exception as e:
            if self.running:
                logger.error(f"Web server error: {e}")

    def start(self):
        if self.running:
            logger.warning("Web server is already running")
            return self
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        return self

    def stop(self):
        if not self.running:
            return
        self.running = False
        try:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
        except Exception:
            pass
        logger.info("Web server stopped")

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class Client:
    """已废弃：不再使用 Socket/CLI。保留占位以避免外部引用崩溃。"""
    def __init__(self, *_, **__):
        raise RuntimeError("Client has been deprecated in web mode. Use HTTP endpoints instead.")


def start_web_console(host: str = "127.0.0.1", port: int = 9090) -> BackgroundServer:
    return BackgroundServer(host=host, port=port).start()