#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/11/27

import os
import subprocess
import json
import platform
from pathlib import Path
from lib.core.log import logger
from lib.core.data import conf, path
from shutil import which
from lib.core.common import generate_random_string
from typing import Dict, Any

class API:
    def __init__(self):
        self.enable = False
        if not self.find_executable():
            return None
        if not self.check_installation():
            return None
        self.enable = True
    
    def find_executable(self):
        # observerward
        self.ward_path = which('observerward') or which('ward') or which('observer_ward')
        if conf.observerward_path != "":
            self.ward_path = conf.observerward_path
        if not self.ward_path:
            logger.warning("ObserverWard executable not found", origin="thirdpart")
            return False
        # nuclei
        self.nuclei_path = which('nuclei')
        if conf.nuclei_path != "":
            self.nuclei_path = conf.nuclei_path
        if not self.nuclei_path:
            logger.warning("Nuclei executable not found", origin="thirdpart")
            return False
        return True
    
    def check_installation(self):
        try:
            # observer_ward
            result = subprocess.run(
                [self.ward_path, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "observer_ward v" in result.stdout or "observer_ward v" in result.stderr:
                version = "Unknown"
                import re
                version_match = re.search(r'observer_ward v(\S+)', result.stdout + result.stderr)
                if version_match:
                    version = version_match.group(1)
                
                logger.info(f"ObserverWard version: {version}", origin="thirdpart")
            else:
                logger.warning(f"ObserverWard execution failed: No version identifier found", origin="thirdpart")
                return False
            # nuclei
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "Nuclei Engine Version" in result.stdout or "Nuclei Engine Version" in result.stderr:
                version = "Unknown"
                import re
                version_match = re.search(r'Nuclei Engine Version: v(\S+)', result.stdout + result.stderr)
                if version_match:
                    version = version_match.group(1)
                logger.info(f"Nuclei version: {version}", origin="thirdpart")
            else:
                logger.warning(f"Nuclei execution failed: No version identifier found", origin="thirdpart")
                return False
            # fingerprints
            system = platform.system().lower()
            username = os.getlogin()
            if "windows" in system:
                user_profile = os.environ.get('USERPROFILE', f'C:\\Users\\{username}')
                file_path = Path(user_profile) / "AppData" / "Roaming" / "observer_ward" / "web_fingerprint_v4.json"
            elif "linux" in system:
                home_dir = os.environ.get('HOME', f'/home/{username}')
                file_path = Path(home_dir) / ".config" / "observer_ward" / "web_fingerprint_v4.json"
            elif "darwin" in system:
                home_dir = os.environ.get('HOME', f'/Users/{username}')
                file_path = Path(home_dir) / "Library" / "Application Support" / "observer_ward" / "web_fingerprint_v4.json"
            else:
                logger.warning(f"Unsupported operating system: {system}", origin="thirdpart")
                return False
            if not file_path.exists():
                logger.warning(f"Fingerprint location not found, try running: observerward --update-fingerprint", origin="thirdpart")
                return False
            logger.info(f"ObserverWard fingerprint path: {file_path}", origin="thirdpart")
            # plugins
            if "windows" in system:
                user_profile = os.environ.get('USERPROFILE', f'C:\\Users\\{username}')
                dir_path = Path(user_profile) / "AppData" / "Roaming" / "observer_ward" / "plugins"
            elif "linux" in system:
                home_dir = os.environ.get('HOME', f'/home/{username}')
                dir_path = Path(home_dir) / ".config" / "observer_ward" / "plugins"
            elif "darwin" in system:
                home_dir = os.environ.get('HOME', f'/Users/{username}')
                dir_path = Path(home_dir) / "Library" / "Application Support" / "observer_ward" / "plugins"
            if not dir_path.exists() and dir_path.is_dir():
                logger.warning(f"ObserverWard-Nuclei plugin location not found, try running: observerward --update-plugin", origin="thirdpart")
                return False
            logger.info(f"ObserverWard-Nuclei plugin set path: {dir_path}", origin="thirdpart")
            return True

        except Exception as e:
            logger.error(f"Third-party check exception: {e}", origin="thirdpart")
            return False
    
    def scan(self, url):
        if self.enable is False:
            return []
        try:
            reportpath = Path(path.temp) / "{}.json".format(generate_random_string())
            # 构建命令
            cmd = [self.ward_path, 
                   "-t", url, 
                   "--format", "json", 
                   "--timeout", str(conf.timeout), 
                    "-o", reportpath, 
                    "--plugin","default"
                   ]
            # 执行扫描
            logger.debug(f"Executing ObserverWard scan: {' '.join(str(item) for item in cmd)}", origin="thirdpart")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                encoding='utf-8'
            )
            logger.debug(result.stdout, origin="thirdpart")
            # 检查执行结果
            if result.returncode != 0:
                logger.error(f"ObserverWard scan failed: {result.stderr}", origin="thirdpart")
                return []
            # 解析输出结果
            return parse_observerward_report(reportpath)
        except Exception as e:
            logger.error(f"ObserverWard scan exception: {e}", origin="thirdpart")
            return []

class ObserverWardParser:
    def __init__(self, json_file_path: str):
        self.json_file_path = json_file_path
        self.data = self._load_json()
    
    def _load_json(self) -> Dict[str, Any]:
        try:
            with open(self.json_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load JSON file: {e}")
            return {}
    
    def parse_and_log(self):
        self.vulns = []
        if not self.data:
            logger.error("No valid data to parse")
            return
        
        for url, scan_data in self.data.items():
            # 基本信息
            title_list = scan_data.get('title', [])
            if title_list and len(title_list) > 0:
                title = title_list[0] or 'No Title'
            else:
                title = 'No Title'
            length = scan_data.get('length', 0)
            status = scan_data.get('status', 0)
            technologies = scan_data.get('name', [])
            # 格式化技术栈显示
            tech_display = ','.join(technologies) if technologies else 'Unknown'
            # 输出基本信息
            logger.info(f"{url} [{tech_display}]  <{title}> <{length}> ({status})", origin="observerward")
            # 处理 Nuclei 漏洞扫描结果
            self._process_nuclei_results(url, scan_data.get('nuclei', {}))
        return self.vulns
    
    def _process_nuclei_results(self, url: str, nuclei_data: Dict[str, Any]):
        for template_name, vuln_list in nuclei_data.items():
            for vulnerability in vuln_list:
                self._generate_vuln_result(url, vulnerability)
    
    def _generate_vuln_result(self, url: str, vulnerability: Dict[str, Any]):
        info = vulnerability.get('info', {})
        
        # 构建结果数据
        result_data = {
            "type": "REQUEST",  # 扫描类型
            "url": url,  # 漏洞URL
            "show": {
                "Template": vulnerability.get('template-id', ''),
                "Name": info.get('name', ''),
                "Severity": info.get('severity', 'info').upper(),
                "Description": info.get('description', '')[:100] + "..." if info.get('description') else "",
                "MatchedAt": vulnerability.get('matched-at', '')
            }
        }
        classification = info.get('classification', {})
        if classification.get('cve-id'):
            result_data['show']['CVE'] = classification['cve-id']
        self.vulns.append(result_data)


def parse_observerward_report(json_file_path: str):
    parser = ObserverWardParser(json_file_path)
    return parser.parse_and_log()
