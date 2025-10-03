#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout, QFileDialog, QLabel

from qfluentwidgets import (
    LineEdit, ComboBox, PushButton, PrimaryPushButton, TextEdit,
    InfoBar, InfoBarPosition, SmoothScrollArea
)

# 尝试导入 FilledPushButton（不同版本可能命名为 FilledButton）
try:
    from qfluentwidgets import FilledPushButton as SaveButton
except Exception:
    try:
        from qfluentwidgets import FilledButton as SaveButton
    except Exception:
        SaveButton = PrimaryPushButton

from qfluentwidgets import Theme, setTheme

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LING_SETTINGS_PATH = os.path.join(BASE_DIR, "config", "ling_settings.json")
CONFIG_PY_PATH = os.path.join(BASE_DIR, "config", "config.py")


def _ensure_dir(p: str):
    d = os.path.dirname(p)
    os.makedirs(d, exist_ok=True)


def load_ling_settings():
    try:
        if os.path.isfile(LING_SETTINGS_PATH):
            with open(LING_SETTINGS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {"exe_path": "", "theme": "LIGHT"}


def save_ling_settings(data) -> bool:
    try:
        _ensure_dir(LING_SETTINGS_PATH)
        with open(LING_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def read_config_py() -> str:
    try:
        with open(CONFIG_PY_PATH, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


class SettingsInterface(QWidget):
    """设置页：仅提供 Ling 设置 + config.py 原文编辑器"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("settingsInterface")

        outer_layout = QVBoxLayout(self)

        # 滚动容器防止长文本溢出
        self.scroll = SmoothScrollArea()
        self.scroll.setWidgetResizable(True)
        container = QWidget()
        self.scroll.setWidget(container)

        main_layout = QVBoxLayout(container)

        # Ling 设置
        ling_group = QGroupBox("Ling 设置")
        ling_form = QFormLayout()

        self.exe_path_edit = LineEdit()
        self.exe_browse_btn = PushButton("选择可执行文件")
        exe_row = QHBoxLayout()
        exe_row.addWidget(self.exe_path_edit)
        exe_row.addWidget(self.exe_browse_btn)
        ling_form.addRow("z0 可执行文件路径:", exe_row)

        self.theme_combo = ComboBox()
        self.theme_combo.addItems(["LIGHT", "DARK"])
        ling_form.addRow("主题模式:", self.theme_combo)

        ling_group.setLayout(ling_form)
        main_layout.addWidget(ling_group)

        # config.py 原文编辑器
        raw_group = QGroupBox("config.py 原文编辑（保存即覆盖原文件，保留注释与结构）")
        raw_layout = QVBoxLayout()
        self.config_raw_edit = TextEdit()
        self.config_raw_edit.setPlaceholderText("在此直接编辑 config/config.py 全文。保存时将覆盖原文件。")
        raw_layout.addWidget(self.config_raw_edit)
        raw_group.setLayout(raw_layout)
        main_layout.addWidget(raw_group)

        # 保存按钮（右下角）
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.save_btn = SaveButton("保存")
        btn_row.addWidget(self.save_btn)
        main_layout.addLayout(btn_row)

        outer_layout.addWidget(self.scroll)

        # 事件绑定
        self.exe_browse_btn.clicked.connect(self._on_browse_exe)
        self.save_btn.clicked.connect(self._on_save)

        # 初始化数据
        self._load_initial()

    def _on_browse_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 z0 可执行文件", os.getcwd(), "可执行文件 (*.exe *.bin *.*)")
        if path:
            self.exe_path_edit.setText(path)

    def _load_initial(self):
        # 载入 Ling 设置
        ling = load_ling_settings()
        self.exe_path_edit.setText(ling.get("exe_path", ""))
        theme = ling.get("theme", "LIGHT").upper()
        self.theme_combo.setCurrentIndex(0 if theme == "LIGHT" else 1)

        # 载入 config.py
        cfg_text = read_config_py()
        if cfg_text:
            self.config_raw_edit.setPlainText(cfg_text)
        else:
            from qfluentwidgets import InfoBar, InfoBarPosition
            InfoBar.warning(title="提示", content="未能读取 config/config.py 或内容为空", position=InfoBarPosition.TOP, parent=self, duration=2500)

    def _on_save(self):
        # 保存 Ling 设置
        theme_val = self.theme_combo.currentText().upper()
        ling_ok = save_ling_settings({
            "exe_path": self.exe_path_edit.text().strip(),
            "theme": theme_val
        })

        # 应用主题
        try:
            setTheme(Theme.DARK if theme_val == "DARK" else Theme.LIGHT)
        except Exception:
            pass

        # 保存 config.py 原文
        raw_text = self.config_raw_edit.toPlainText()
        if not raw_text.strip():
            InfoBar.warning(title="提示", content="config.py 内容为空，未保存", position=InfoBarPosition.TOP, parent=self, duration=2500)
            return
        try:
            with open(CONFIG_PY_PATH, "w", encoding="utf-8") as f:
                f.write(raw_text)
            InfoBar.success(title="成功", content="设置已保存（Ling 设置与 config.py）", position=InfoBarPosition.TOP, parent=self, duration=2500)
        except Exception as e:
            InfoBar.error(title="错误", content=f"保存失败: {str(e)}", position=InfoBarPosition.TOP, parent=self, duration=3000)