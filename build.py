#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/17

import os
import re
import sys
import platform
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
import zipfile


def find_nuitka():
    """查找nuitka可执行文件的完整路径"""
    nuitka_path = which('nuitka')
    if nuitka_path:
        return [nuitka_path]
    return [sys.executable, '-m', 'nuitka']

def find_pyinstaller():
    """查找nuitka可执行文件的完整路径"""
    pyinstaller_path = which('pyinstaller')
    if pyinstaller_path:
        return [pyinstaller_path]
    return [sys.executable, '-m', 'pyinstaller']

def get_platform_specific_args():
    """返回平台特定的Nuitka编译参数"""
    args = []
    system = platform.system().lower()
    
    # Windows特定参数
    if system == 'windows':
        args.extend([
            '--windows-icon-from-ico=doc/logo.png',
        ])
    
    # macOS特定参数
    elif system == 'darwin':
        args.extend([
            '--macos-app-icon=doc/logo.png',
        ])
    
    # Linux特定参数
    elif system == 'linux':
        args.extend([
            '--linux-icon=doc/logo.png'
        ])
    
    return args

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
        'psycopg2-binary': 'psycopg2', 
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
    
    # 基础编译参数
    base_args = [
        # '--lto=yes' if platform.system().lower() != 'darwin' else '--lto=no',  # macOS下禁用LTO
        '--lto=no',
        '--output-dir=z0scan', 
        '--standalone',
        '--onefile',
        '--python-flag=-u', 
        '--include-package=lib',
        '--nofollow-import-to=config',
        '--include-package=api',
        "--include-data-file=doc/tld-patch/effective_tld_names.dat.txt=tld/res/effective_tld_names.dat.txt",
        '--remove-output', 
        '--nofollow-import-to=*.tests,*.test', 
        '--assume-yes-for-downloads',
    ]
    nuitka_cmd.extend(base_args)
    
    # 添加平台特定参数
    platform_args = get_platform_specific_args()
    nuitka_cmd.extend(platform_args)

    # 依赖处理（与release.yml配合）
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
                
                if not verify_import(pkg_name, actual_name):
                    missing_modules.append(f"{pkg_name} -> {actual_name}")
                    continue
                
                # 添加包含指令（优化插件支持）
                nuitka_cmd.extend([
                    f"--include-module={actual_name}",
                    f"--include-package={actual_name}",
                ])

    if missing_modules:
        print("\n:: Warning: Missing modules detected (will continue for CI):")
        for mod in missing_modules:
            print(f"  - {mod}")
        if not os.getenv('CI'):  # 非CI环境才询问
            if input("Continue compiling? (y/n): ").lower() != 'y':
                sys.exit(1)

    nuitka_cmd.append('z0.py')
    
    # 在CI环境中显示完整命令
    if os.getenv('CI'):
        print('\n:: NUITKA COMMAND :', ' '.join(nuitka_cmd))
    
    try:
        subprocess.run(nuitka_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'\n:: BUILD FAILED (CODE {e.returncode})')
        sys.exit(1)


def build_ling():
    pyinstaller_cmd = find_pyinstaller()
    
    # 基础编译参数
    base_args = [
        '-F',
        '-w', 
        '--icon=doc/logo.png',
        '--distpath=z0scan',
        '--add-data=doc/logo.png:doc',
        '--add-data=ling.qss:.',
    ]
    pyinstaller_cmd.extend(base_args)

    pyinstaller_cmd.append('ling.py')
    # 在CI环境中显示完整命令
    if os.getenv('CI'):
        print('\n:: PYINSTALLER COMMAND :', ' '.join(pyinstaller_cmd))
    
    try:
        subprocess.run(pyinstaller_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'\n:: BUILD FAILED (CODE {e.returncode})')
        sys.exit(1)
    
def setup_build_directory():
    """优化资源文件处理，与release.yml配合"""
    # 需要复制的资源文件
    resource_dirs = ['scanners', 'config', 'fingerprints', 'data']
    
    build_dir = Path('z0scan')
    try:
        build_dir.mkdir(exist_ok=True)
        for item in resource_dirs:
            src = Path(item)
            dst = build_dir / item
            
            if src.exists():
                if src.is_file():
                    copy2(src, dst)
                elif src.is_dir():
                    copytree(src, dst, dirs_exist_ok=True)
    except Exception as e:
        print(f"\n:: RESOURCE COPY ERROR: {str(e)}")
        if not os.getenv('CI'):  # CI环境中忽略资源错误
            sys.exit(1)

    # Create zip archive
    system = platform.system().lower()
    arch = platform.machine().lower()
    zip_filename = f"z0scan-{system}-{arch}.zip"
    
    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in build_dir.rglob('*'):
                if file.is_file():
                    arcname = file.relative_to(build_dir.parent)
                    zipf.write(file, arcname)
        
        print(f"\n:: CREAT SUCCESS : {zip_filename}")
        return True
    
    except Exception as e:
        print(f"\n:: RESOURCE ZIP ERROR: {e}")
        return False

if __name__ == '__main__':
    try:
        build()
        build_ling()
        setup_build_directory()
        print("\n:: BUILD SUCCESS ::")
    except KeyboardInterrupt:
        print("\n:: BUILD INTERRUPTED ::")
        sys.exit(1)