#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

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
from datetime import datetime

def find_nuitka():
    """查找nuitka可执行文件的完整路径"""
    nuitka_path = which('nuitka')
    if nuitka_path:
        return [nuitka_path]
    return [sys.executable, '-m', 'nuitka']

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


def find_built_binary(build_dir: Path) -> Path:
    """
    在给定的构建输出目录中查找 Nuitka --onefile 产物的可执行文件。
    优先返回：
      - Windows: *.exe
      - 其他平台: 无扩展或 .bin
    """
    if not build_dir.exists():
        return None
    candidates = []
    for p in build_dir.iterdir():
        if not p.is_file():
            continue
        name = p.name.lower()
        if os.name == "nt":
            if name.endswith(".exe"):
                candidates.append(p)
        else:
            if not "." in name or name.endswith(".bin"):
                candidates.append(p)
    if not candidates:
        return None
    # 选最近修改的一个
    candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return candidates[0]

def maybe_upx_compress(build_dir: Path):
    """
    条件执行 UPX 压缩：
      - 通过 ENABLE_UPX=1 开启
      - 可用 UPX_PATH 指定 upx 二进制路径
      - 可用 UPX_FLAGS 自定义参数（默认 '--best --lzma'）
    """
    if platform.system().lower() == 'darwin':
        return
    upx_bin = os.getenv("UPX_PATH") or which("upx")
    if not upx_bin:
        print(":: UPX SKIP: upx not found (set UPX_PATH or install upx)")
        return

    target = find_built_binary(build_dir)
    if not target:
        print(":: UPX SKIP: built binary not found in", build_dir)
        return

    flags = os.getenv("UPX_FLAGS", "--best --lzma")
    cmd = [upx_bin, *flags.split(), str(target)]
    print(":: UPX RUN :", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
        print(f":: UPX DONE: {target.name} compressed at {datetime.now().isoformat(timespec='seconds')}")
    except subprocess.CalledProcessError as e:
        print(f":: UPX ERROR: exit {e.returncode} (skip)")

def build():
    nuitka_cmd = find_nuitka()
    
    # 基础编译参数
    base_args = [
        '--lto=yes' if platform.system().lower() == 'linux' else '--lto=no',  # macOS下禁用LTO
        '--output-dir=z0scan', 
        '--standalone',
        '--onefile',
        '--python-flag=-u', 
        '--include-plugin-directory=scanners', # 把scanners导入
        "--include-data-file=patch/effective_tld_names.dat.txt=tld/res/effective_tld_names.dat.txt",
        '--include-data-dir=bin=bin', # crawlergo
        '--include-data-dir=data=data', # db
        '--follow-imports', 
        '--nofollow-import-to=config', # config 动态导入
        '--nofollow-import-to=*.tests,*.test', 
        '--noinclude-setuptools-mode=nofollow', 
        '--noinclude-pytest-mode=nofollow', 
        '--remove-output', 
        '--assume-yes-for-downloads',
        '--include-package-data=dateutil', 
        '--include-package-data=dateutil.zoneinfo', 
    ]
    nuitka_cmd.extend(base_args)
    
    # 添加平台特定参数
    platform_args = get_platform_specific_args()
    nuitka_cmd.extend(platform_args)
    nuitka_cmd.append('z0.py')
    
    # 在CI环境中显示完整命令
    if os.getenv('CI'):
        print('\n:: NUITKA COMMAND :', ' '.join(nuitka_cmd))
    
    try:
        subprocess.run(nuitka_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'\n:: BUILD FAILED (CODE {e.returncode})')
        sys.exit(1)

    # 构建完成后，尝试进行 UPX 压缩（可选）
    try:
        maybe_upx_compress(Path('z0scan'))
    except Exception as _e:
        print(f":: UPX SKIP (exception): {_e}")
    
def setup_build_directory():
    """优化资源文件处理，与release.yml配合"""
    # 需要复制的资源文件
    resource_dirs = ['config.py', 'dicts']
    
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
        setup_build_directory()
        print("\n:: BUILD SUCCESS ::")
    except KeyboardInterrupt:
        print("\n:: BUILD INTERRUPTED ::")
        sys.exit(1)
