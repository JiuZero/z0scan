# -*- coding: utf-8 -*-

import os
from typing import Dict, Any, Union
import requests
from packaging import version

from lib.core.log import logger


def _fetch_latest_release(github_repo: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{github_repo}/releases/latest"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Z0SCAN",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def check_update(github_repo: str, current_version: str) -> Union[Dict[str, Any], bool]:
    """
    检测是否存在新版本。
    - 无更新或出现错误时：返回 False
    - 有更新时：返回包含关键信息的字典
    """
    try:
        data = _fetch_latest_release(github_repo)
        latest_ver_str = (data.get("tag_name") or "").lstrip("v").strip()
        if not latest_ver_str:
            return False
        latest_ver = version.parse(latest_ver_str)
        cur_ver = version.parse(str(current_version).strip())
        if latest_ver <= cur_ver:
            return False
        # 组织返回数据
        info: Dict[str, Any] = {
            "latest_version": latest_ver_str,
            "name": data.get("name"),
            "body": data.get("body"),
            "published_at": data.get("published_at"),
            "html_url": data.get("html_url"),
            "assets": [],
        }
        for asset in data.get("assets", []) or []:
            info["assets"].append({
                "name": asset.get("name"),
                "size": asset.get("size"),
                "download_url": asset.get("browser_download_url"),
                "content_type": asset.get("content_type"),
            })
        return info
    except requests.exceptions.RequestException as e:
        return False
    except Exception as e:
        logger.error(f"Check update fail: {e}")
        return False