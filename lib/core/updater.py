# -*- coding: utf-8 -*-
"""
自动更新模块
提供基于GitHub Releases的版本检测和自动更新功能
"""

import os, sys, json, time, shutil, zipfile
import tempfile
import subprocess
from typing import Optional, Dict, Any, Callable
import requests
from packaging import version

from lib.core.log import logger

def dataToStdout(data, bold=False):
    """
    Writes text to the stdout (console) stream
    """
    sys.stdout.write(data)
    try:
        sys.stdout.flush()
    except IOError:
        pass
    return
    
def is_frozen() -> bool:
	"""检测是否为打包运行"""
	try:
		if getattr(sys, "frozen", False):
			return True
		return False
	except Exception:
		return False


class UpdateChecker:
    """版本检测器"""
    
    def __init__(self, github_repo: str, current_version: str):
        """
        初始化更新检测器
        
        Args:
            github_repo: GitHub仓库地址，格式为 'owner/repo'
            current_version: 当前版本号
        """
        self.github_repo = github_repo
        self.current_version = current_version
        self.api_base = "https://api.github.com"
        
    def get_latest_release(self) -> Optional[Dict[str, Any]]:
        """
        获取最新版本信息
        Returns:
            最新版本信息字典，包含版本号、下载链接等
        """
        try:
            url = f"{self.api_base}/repos/{self.github_repo}/releases/latest"
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Z0SCAN'
            }
            token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
            if token:
                headers['Authorization'] = f'Bearer {token}'
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()   
            release_data = response.json()
            # 解析版本信息
            release_info = {
                'version': release_data['tag_name'].lstrip('v'),
                'name': release_data['name'],
                'body': release_data['body'],
                'published_at': release_data['published_at'],
                'html_url': release_data['html_url'],
                'assets': []
            }
            # 解析下载链接
            for asset in release_data.get('assets', []):
                asset_info = {
                    'name': asset['name'],
                    'size': asset['size'],
                    'download_url': asset['browser_download_url'],
                    'content_type': asset['content_type']
                }
                release_info['assets'].append(asset_info)
            return release_info
        except requests.exceptions.RequestException as e:
            logger.info(f"检查更新失败: {e}")
            return None
        except Exception as e:
            logger.info(f"解析版本信息失败: {e}")
            return None
    
    def has_update(self) -> bool:
        """
        检查是否有新版本
        Returns:
            是否有新版本
        """
        latest_release = self.get_latest_release()
        if not latest_release:
            return False
        try:
            latest_version = latest_release['version']
            current_version = self.current_version
            # 使用packaging.version比较
            latest_ver = version.parse(latest_version)
            current_ver = version.parse(current_version)
            return latest_ver > current_ver
        except Exception as e:
            logger.info(f"版本比较失败: {e}")
            return False
    
    def get_update_info(self) -> Optional[Dict[str, Any]]:
        """
        获取更新信息（版本号、更新内容等）
        Returns:
            更新信息字典
        """
        if not self.has_update():
            return None
        return self.get_latest_release()


class AutoUpdater:
    """自动更新器"""
    
    def __init__(self, github_repo: str, current_version: str):
        """
        初始化自动更新器
        
        Args:
            github_repo: GitHub仓库地址
            current_version: 当前版本号
        """
        self.github_repo = github_repo
        self.current_version = current_version
        self.checker = UpdateChecker(github_repo, current_version)
        self.download_progress = 0
        self.download_total = 0
        self.is_downloading = False
    
    def update(self) -> Optional[Dict[str, Any]]:
        """
        检查更新并安装更新
        """
        update_info = self.checker.get_update_info()
        if update_info:
            file_path = self.download_update(update_info)
            if file_path:
                self.install_update(file_path)
        return None
    
    def check_for_updates(self) -> Optional[Dict[str, Any]]:
        """
        检查更新
        Returns:
            更新信息
        """
        _ = self.checker.get_update_info()
        return _ if _ else None
        
    def _get_platform_asset(self, assets: list) -> Optional[Dict[str, Any]]:
        """
        根据平台选择合适的下载文件
        Args:
            assets: 资源列表
        Returns:
            合适的资源信息
        """
        platform = sys.platform.lower()
        # 根据平台定义优先级检查函数
        if platform == 'win32':
            predicates = [
                lambda n: n.endswith('.exe') and ('win' in n or 'windows' in n),
                lambda n: ('win' in n or 'windows' in n) and n.endswith('.zip'),
                lambda n: n.endswith('.zip')
            ]
        elif platform.startswith('linux'):
            predicates = [
                lambda n: n.endswith(('.appimage', '.appimage')),  # AppImage优先
                lambda n: ('linux' in n) and (n.endswith('.tar.gz') or n.endswith('.tgz')),
                lambda n: ('linux' in n) and n.endswith('.zip'),
                lambda n: (n.endswith('.tar.gz') or n.endswith('.tgz')),
                lambda n: n.endswith('.zip')
            ]
        elif platform == 'darwin':
            predicates = [
                lambda n: n.endswith('.dmg'),
                lambda n: ('mac' in n or 'darwin' in n) and n.endswith('.zip'),
                lambda n: n.endswith('.zip')
            ]
        else:
            predicates = [lambda n: n.endswith('.zip')]
        assets_by_name = [(asset, asset['name'].lower()) for asset in assets]
        for pred in predicates:
            for asset, lower_name in assets_by_name:
                try:
                    if pred(lower_name):
                        return asset
                except Exception:
                    continue
        return None
    
    def download_update(self, update_info: Dict[str, Any]) -> Optional[str]:
        """
        下载更新
        Args:
            update_info: 更新信息
        Returns:
            下载的文件路径
        """
        # 仅允许官方发布版自动更新
        if not is_frozen():
            return None
        if self.is_downloading:
            return None
        self.is_downloading = True
        try:
            # 选择合适的下载文件
            asset = self._get_platform_asset(update_info['assets'])
            if not asset:
                raise Exception("没有找到适合当前平台的更新文件")
            # 创建临时文件
            temp_dir = tempfile.gettempdir()
            file_path = os.path.join(temp_dir, asset['name'])
            # 下载文件
            headers = {
                'User-Agent': 'Z0SCAN',
                'Accept': 'application/octet-stream'
            }
            token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
            if token:
                headers['Authorization'] = f'Bearer {token}'
            response = requests.get(asset['download_url'], headers=headers, stream=True, timeout=30)
            response.raise_for_status()
            self.download_total = int(response.headers.get('content-length', 0))
            self.download_progress = 0
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        self.download_progress += len(chunk)
                        dataToStdout(f'{self.download_progress} | Sizes: {self.download_total}')
            # 简单完整性校验（如有Content-Length）
            if self.download_total > 0 and os.path.getsize(file_path) != self.download_total:
                raise Exception("下载文件大小与预期不一致")
            return file_path
        except Exception as e:
            logger.info(f"下载更新失败: {e}")
            return None
        finally:
            self.is_downloading = False
    
    def install_update(self, update_file: str, restart: bool = True) -> bool:
        """
        安装更新

        Args:
            update_file: 更新文件路径
            restart: 是否重启应用

        Returns:
            是否安装成功
        """
        # 仅允许官方发布版自动更新
        if not is_frozen():
            return False
        try:
            # 预检查：确保更新文件存在且可读
            if not os.path.exists(update_file):
                raise Exception(f"更新文件不存在: {update_file}")
            if not os.access(update_file, os.R_OK):
                raise Exception(f"无法读取更新文件: {update_file}")
            logger.debug(f"更新文件验证通过: {update_file}")
            # 预检查：确保当前程序目录可写
            current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            if not os.access(current_dir, os.W_OK):
                raise Exception(f"程序目录无写入权限: {current_dir}")
            logger.debug(f"程序目录权限检查通过: {current_dir}")
            # 根据文件类型处理
            if update_file.endswith('.zip'):
                # ZIP压缩包
                logger.debug("使用ZIP压缩包更新模式")
                self._install_from_zip(update_file, restart)
            elif update_file.endswith('.tar.gz') or update_file.endswith('.tgz'):
                # tarball 压缩包（常见于Linux）
                logger.debug("使用TAR.GZ压缩包更新模式")
                self._install_from_tarball(update_file, restart)
            else:
                raise Exception(f"不支持的更新文件类型: {update_file}")
            return True
        except Exception as e:
            error_msg = f"安装更新失败: {e}"
            logger.error(error_msg)
            return False
    
    def _install_windows_exe(self, exe_path: str, restart: bool):
        """安装Windows可执行文件（调用外部批处理脚本接管更新）"""
        current_pid = os.getpid()
        current_exe = sys.executable
        helper_name = 'update_helper.bat'
        helper_path = os.path.join(tempfile.gettempdir(), helper_name)
        helper_script = f"""
@echo off
setlocal enabledelayedexpansion

REM 参数：当前PID、当前EXE路径、下载的更新文件路径、是否重启(True/False)
set target_pid={current_pid}
set current_exe="{current_exe}"
set update_file="{exe_path}"
set do_restart={str(restart)}

echo [Updater] 准备关闭进程 !target_pid! 并执行文件替换
taskkill /PID !target_pid! /F >nul 2>&1
timeout /t 2 /nobreak > nul

REM 等待退出，最多15次
set /a count=0
:wait_exit
tasklist /FI "PID eq !target_pid!" 2>nul | find "!target_pid!" >nul
if errorlevel 1 goto do_update
set /a count+=1
if !count! geq 15 (
    echo [Updater] 进程未退出，继续强制更新
    goto do_update
)
timeout /t 1 /nobreak > nul
goto wait_exit

:do_update
echo [Updater] 开始更新文件
REM 备份旧文件
if exist !current_exe! (
    copy /y !current_exe! !current_exe!.backup >nul 2>&1
)

REM 替换新文件（带重试）
set /a retry=0
:replace_retry
move /y !update_file! !current_exe! >nul 2>&1
if errorlevel 1 (
    set /a retry+=1
    if !retry! lss 5 (
        echo [Updater] 替换失败，重试 !retry!/5
        timeout /t 1 /nobreak > nul
        goto replace_retry
    ) else (
        echo [Updater] 替换失败，尝试恢复备份
        if exist !current_exe!.backup (
            move /y !current_exe!.backup !current_exe! >nul 2>&1
        )
        goto end
    )
)

REM 清理备份
if exist !current_exe!.backup (
    del /f /q !current_exe!.backup >nul 2>&1
)

if "!do_restart!"=="True" (
    echo [Updater] 重启程序
    start "" !current_exe!
)

:end
exit /b 0
"""
        with open(helper_path, 'w', encoding='gbk') as f:
            f.write(helper_script)
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
        creationflags = DETACHED_PROCESS | CREATE_NO_WINDOW
        subprocess.Popen(['cmd', '/c', helper_path], creationflags=creationflags)
        logger.info('外部更新程序已启动，应用将退出以完成更新...')
        time.sleep(0.5)
        sys.exit(0)
    
    def _install_from_zip(self, zip_path: str, restart: bool):
        """从ZIP文件安装更新"""
        # 解压到临时目录
        temp_extract_dir = os.path.join(tempfile.gettempdir(), 'update_extract')
        os.makedirs(temp_extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_dir)
        # 获取当前程序目录
        app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        # 创建更新脚本
        if sys.platform == 'win32':
            self._create_windows_update_script(temp_extract_dir, app_dir, restart)
        else:
            self._create_unix_update_script(temp_extract_dir, app_dir, restart)
    
    def _create_windows_update_script(self, source_dir: str, target_dir: str, restart: bool):
        """创建Windows更新脚本"""
        current_pid = os.getpid()
        exe_name = os.path.basename(sys.executable)
        script = f"""
@echo off
setlocal enabledelayedexpansion
echo 等待程序退出...

REM 强制结束当前进程
taskkill /PID {current_pid} /F >nul 2>&1
timeout /t 2 /nobreak > nul

REM 等待进程完全退出，最多等待10秒
set /a count=0
:wait_loop
tasklist /FI "PID eq {current_pid}" 2>nul | find "{current_pid}" >nul
if errorlevel 1 goto process_ended
set /a count+=1
if %count% geq 10 (
    echo 警告：程序未在预期时间内退出，强制终止进程
    taskkill /PID {current_pid} /F >nul 2>&1
    timeout /t 1 /nobreak > nul
    goto process_ended
)
timeout /t 1 /nobreak > nul
goto wait_loop

:process_ended
echo 开始更新程序文件...

REM 创建备份目录
if not exist "{target_dir}\\backup" mkdir "{target_dir}\\backup" 2>nul
if errorlevel 1 (
    echo 警告：无法创建备份目录，尝试继续更新
)

REM 备份重要文件
if exist "{target_dir}\\{exe_name}" (
    echo 创建备份...
    copy "{target_dir}\\{exe_name}" "{target_dir}\\backup\\{exe_name}.backup" >nul 2>&1
    if errorlevel 1 (
        echo 警告：无法创建备份文件，尝试继续更新
    ) else (
        echo 备份文件已创建
    )
)

REM 复制新文件
echo 复制更新文件...
xcopy /s /e /y /h /r "{source_dir}\\*" "{target_dir}\\" >nul 2>&1
if %errorlevel% == 0 (
    echo 更新成功完成
    REM 清理临时文件
    if exist "{source_dir}" (
        rmdir /s /q "{source_dir}" 2>nul
    )

    REM 删除备份
    if exist "{target_dir}\\backup\\{exe_name}.backup" (
        echo 清理备份文件...
        set /a retry=0
        :cleanup_backup_retry
        del "{target_dir}\\backup\\{exe_name}.backup" 2>nul
        if exist "{target_dir}\\backup\\{exe_name}.backup" (
            set /a retry+=1
            if !retry! lss 3 (
                echo 重试删除备份文件 (!retry!/3)...
                timeout /t 1 /nobreak > nul
                goto cleanup_backup_retry
            ) else (
                echo 警告：无法删除备份文件，将在下次启动时清理
            )
        ) else (
            echo 备份文件已清理
        )
    )

    REM 清理空的备份目录
    if exist "{target_dir}\\backup" (
        dir /b "{target_dir}\\backup" 2>nul | findstr "." >nul
        if errorlevel 1 (
            rmdir "{target_dir}\\backup" 2>nul
        )
    )

    if "{restart}" == "True" (
        echo 重启程序...
        cd /d "{target_dir}"
        start "" "{exe_name}"
        goto end_script
    )
) else (
    echo 错误：文件复制失败，尝试恢复备份
    if exist "{target_dir}\\backup\\{exe_name}.backup" (
        copy "{target_dir}\\backup\\{exe_name}.backup" "{target_dir}\\{exe_name}" >nul 2>&1
        if errorlevel 1 (
            echo 错误：无法恢复备份文件
        ) else (
            echo 已恢复原程序文件
        )
    )
    goto cleanup
)

:cleanup
echo 更新失败，清理临时文件...

:end_script
REM 确保脚本文件存在后再删除
if exist "%~f0" (
    timeout /t 1 /nobreak > nul
    del "%~f0" 2>nul
)
"""
        script_file = os.path.join(tempfile.gettempdir(), 'update.bat')
        with open(script_file, 'w', encoding='gbk') as f:  # 使用gbk编码避免中文乱码
            f.write(script)
        # 通知用户程序即将退出
        subprocess.Popen(script_file, shell=True)
        sys.exit(0)
    
    def _create_unix_update_script(self, source_dir: str, target_dir: str, restart: bool):
        """创建Unix更新脚本"""
        current_pid = os.getpid()
        exe_name = os.path.basename(sys.executable)
        script = f"""#!/bin/bash
echo "等待程序退出..."

# 等待当前进程退出，最多等待30秒
count=0
while [ $count -lt 30 ]; do
    if ! kill -0 {current_pid} 2>/dev/null; then
        break
    fi
    count=$((count + 1))
    sleep 1
done

if kill -0 {current_pid} 2>/dev/null; then
    echo "警告：程序未在预期时间内退出，强制继续更新"
fi

echo "开始更新程序文件..."

# 创建备份目录
mkdir -p "{target_dir}/backup"

# 备份重要文件
if [ -f "{target_dir}/{exe_name}" ]; then
    cp "{target_dir}/{exe_name}" "{target_dir}/backup/{exe_name}.backup" 2>/dev/null
fi

# 复制新文件
if cp -rf "{source_dir}"/* "{target_dir}/"; then
    echo "更新成功完成"
    rm -rf "{source_dir}" 2>/dev/null
    # 删除备份（更新成功后）
    rm -rf "{target_dir}/backup" 2>/dev/null

    if [ "{restart}" = "True" ]; then
        echo "重启程序..."
        cd "{target_dir}"
        nohup ./{exe_name} > /dev/null 2>&1 &
    fi
else
    echo "错误：更新失败，尝试恢复备份"
    if [ -f "{target_dir}/backup/{exe_name}.backup" ]; then
        cp "{target_dir}/backup/{exe_name}.backup" "{target_dir}/{exe_name}" 2>/dev/null
        echo "已恢复原程序文件"
    fi
    read -p "按回车键继续..."
fi

rm -f "$0"
"""
        script_file = os.path.join(tempfile.gettempdir(), 'update.sh')
        with open(script_file, 'w') as f:
            f.write(script)
        os.chmod(script_file, 0o755)
        # 通知用户程序即将退出
        logger.info('程序即将退出以完成更新...')
        subprocess.Popen(['/bin/bash', script_file])
        sys.exit(0)

    def _install_from_tarball(self, tar_path: str, restart: bool):
        """从tar.gz或tgz安装更新（Unix平台）"""
        import tarfile
        # 解压到临时目录
        temp_extract_dir = os.path.join(tempfile.gettempdir(), 'update_extract')
        os.makedirs(temp_extract_dir, exist_ok=True)
        with tarfile.open(tar_path, 'r:gz') as tar:
            tar.extractall(temp_extract_dir)
        # 生成脚本
        app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self._create_unix_update_script(temp_extract_dir, app_dir, restart)