#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/17

import os
import re
import sys
import subprocess
from shutil import which, copytree, copy2
from pathlib import Path
from importlib.metadata import distribution, PackageNotFoundError
try:
    from pkg_resources import get_distribution
except ImportError:
    get_distribution = None
import importlib
import pkgutil


def find_nuitka():
    """查找nuitka可执行文件的完整路径"""
    nuitka_path = which('nuitka')
    if nuitka_path:
        return [nuitka_path]
    return [sys.executable, '-m', 'nuitka']

def get_actual_module_name(pkg_name):
    """更可靠的模块名检测方案"""
    # 1. 首先尝试直接导入
    try:
        module = importlib.import_module(pkg_name)
        return module.__name__.split('.')[0]  # 返回顶级包名
    except ImportError:
        pass
    common_variants = {
        'pyzmq': 'zmq',
        'Pillow': 'PIL',
        'python-dateutil': 'dateutil',
        'pyyaml': 'yaml',
        'beautifulsoup4': 'bs4',
        'dnspython': 'dns',
        'pyOpenSSL': 'OpenSSL',
        'PySocks': 'socks', 
        'requests-toolbelt': 'requests_toolbelt', 
    }
    if pkg_name in common_variants:
        return common_variants[pkg_name]
    # 3. 尝试通过元数据检测
    try:
        # Python 3.8+ 现代方法
        try:
            dist = distribution(pkg_name)
            if dist is not None:
                # 方法1: 检查包的顶级模块
                if dist.files:
                    for file in dist.files:
                        parts = file.parts
                        if len(parts) > 0 and parts[0].endswith('.py'):
                            return parts[0][:-3]  # 移除.py后缀
                # 方法2: 检查importlib导入
                for finder in pkgutil.iter_importers():
                    if finder.find_spec(pkg_name):
                        return pkg_name
        except PackageNotFoundError:
            pass
        # 回退到pkg_resources
        if get_distribution is not None:
            dist = get_distribution(pkg_name)
            if dist.has_metadata('top_level.txt'):
                top_level = dist.get_metadata('top_level.txt')
                if top_level:
                    return top_level.split('\n')[0].strip()
    except Exception:
        pass
    # 4. 最终回退到原始名称
    return pkg_name

def verify_import(pkg_name, actual_name):
    """验证模块是否可以导入"""
    try:
        __import__(actual_name)
        return True
    except ImportError:
        try:
            # 尝试直接导入原始名称（某些包可能同时注册多个名称）
            __import__(pkg_name)
            return True
        except ImportError:
            return False

def build():
    nuitka_cmd = find_nuitka()
    nuitka_cmd.extend([
        '--lto=no',
        '--output-dir=build',
        '--standalone',
        '--onefile',
        '--python-flag=-u', 
        '--nofollow-import-to=config',
        '--include-package=lib',
        '--include-package=api',
        "--include-data-file=doc/tld-patch/effective_tld_names.dat.txt=tld/res/effective_tld_names.dat.txt",
    ])

    if not os.path.isfile("requirements.txt"):
        print("Error: requirements.txt not found!")
        sys.exit(1)
    
    missing_modules = []
    with open("requirements.txt", "r") as f:
        for line in f:
            line = line.split('#')[0].strip()
            if line:
                pkg_name = re.split(r'[=<>~\[\]]', line)[0]
                actual_name = get_actual_module_name(pkg_name)
                # 验证模块是否可以导入
                if not verify_import(pkg_name, actual_name):
                    missing_modules.append(f"{pkg_name} -> {actual_name}")
                    continue
                # 添加包含指令
                nuitka_cmd.extend([
                    f"--include-module={actual_name}",
                    f"--include-package={actual_name}",
                ])

    if missing_modules:
        print("\n:: Warning: The following modules cannot be imported, please check the installation.")
        for mod in missing_modules:
            print(f"  - {mod}")
        print("\n:: It is recommended to try again after executing the command: pip install " + " ".join(m.split(' -> ')[0] for m in missing_modules))
        if input("Continue compiling? (y/n): ").lower() != 'y':
            sys.exit(1)

    nuitka_cmd.append('z0.py')
    print('\n:: CMD :', ' '.join(nuitka_cmd))
    
    try:
        subprocess.run(nuitka_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'\n:: ERROR (CODE {e.returncode}) :')
        sys.exit(1)

def setup_build_directory():
    # 定义需要复制的文件/文件夹列表
    items_to_copy = ['scanners', 'config', 'fingerprints', 'data']  # 根据实际情况修改
    
    # 创建build和output目录
    build_dir = Path('build')
    output_dir = build_dir / 'output'
    certs_dir = build_dir / 'certs'
    
    try:
        # 创建目录（exist_ok=True表示如果目录已存在不会报错）
        build_dir.mkdir(exist_ok=True)
        output_dir.mkdir(exist_ok=True)
        certs_dir.mkdir(exist_ok=True)
        
        # 复制文件/文件夹
        for item in items_to_copy:
            src = Path(item)
            dst = build_dir / item
            
            if src.exists():
                if src.is_file():
                    copy2(src, dst)
                elif src.is_dir():
                    copytree(src, dst, dirs_exist_ok=True)       
    except Exception as e:
        print(f"\n:: ERROR (CODE {e.returncode}) :{e}")

if __name__ == '__main__':
    try:
        build()
        setup_build_directory()
    except KeyboardInterrupt:
        print("\n:: Stop...")
        sys.exit(1)