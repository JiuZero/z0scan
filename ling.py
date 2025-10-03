#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @File    : z0scan_gui.py

from time import sleep
import sys
import os
import subprocess
import re
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, 
                            QCheckBox, QComboBox, QGroupBox, QFormLayout, QProgressBar,
                            QFileDialog, QSplitter, QListWidget, QListWidgetItem,
                            QTreeWidget, QTreeWidgetItem, QButtonGroup,
                            QMessageBox, QHeaderView, QDialog, QDialogButtonBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDateTime, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon
from qfluentwidgets import CheckBox, ComboBox, PushButton, PrimaryPushButton, LineEdit, TextEdit, ProgressBar, TreeWidget, ListWidget, InfoBar, InfoBarPosition, FluentWindow, NavigationItemPosition, FluentIcon, Theme, setTheme, SplashScreen, IndeterminateProgressBar

# 插件信息提取正则表达式
PLUGIN_INFO_PATTERNS = {
    'name': re.compile(r'name\s*=\s*["\'](.*?)["\']'),
    'desc': re.compile(r'desc\s*=\s*["\'](.*?)["\']'),
    'version': re.compile(r'version\s*=\s*["\'](.*?)["\']'),
    'risk': re.compile(r'risk\s*=\s*(\d+)')
}

# 用于匹配JSON报告路径的正则表达式
JSON_REPORT_PATH_PATTERN = re.compile(r'JSON Report Path: (.*\.json)')

INFO = """
<h2 style="text-align: center;">z0scan-ling 漏洞扫描工具</h2>
<p style="text-align: center;">版本: 0.0.1</p>
<hr>
<p>z0scan 是一款功能强大的网络漏洞扫描工具，旨在帮助安全测试人员发现和评估网络应用中的安全漏洞。</p>
<p>ling 则作为z0的GUI实现，具有直观、便捷等特点。</p>
<hr>
<p style="text-align: center;">© 2025 JiuZero</p>
"""

def get_resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        # 打包后的环境
        base_path = sys._MEIPASS
    else:
        # 开发环境
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

class AboutDialog(QDialog):
    """关于页面对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于 Ling")
        self.setMinimumSize(400, 300)
        layout = QVBoxLayout(self)
        # 程序信息
        info_text = TextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet("background-color: transparent; border: none;")
        info_text.setHtml(INFO)
        layout.addWidget(info_text)
        # 按钮
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class RiskSelectionDialog(QDialog):
    """风险等级选择对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择风险等级")
        self.setMinimumWidth(300)
        layout = QVBoxLayout(self)
        # 风险等级选项
        self.risk_options = {
            0: CheckBox("0 (极低&信息)"),
            1: CheckBox("1 (低)"),
            2: CheckBox("2 (中)"),
            3: CheckBox("3 (高)")
        }
        # 默认全选
        for cb in self.risk_options.values():
            cb.setChecked(True)
            layout.addWidget(cb)
        # 按钮
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def get_selected_risks(self):
        """获取选中的风险等级"""
        return [level for level, cb in self.risk_options.items() if cb.isChecked()]


class ScanThread(QThread):
    """扫描线程，用于在后台执行扫描任务"""
    output_signal = pyqtSignal(str)
    finish_signal = pyqtSignal(str)  # 传递JSON报告路径
    progress_signal = pyqtSignal(int)

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.running = True
        self.json_report_path = None  # 存储JSON报告路径
        self.process = None  # 子进程句柄

    def run(self):
        try:
            # 执行扫描命令
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True,
                bufsize=1
            )
            # 实时读取输出并查找JSON报告路径
            while self.running and self.process.poll() is None:
                line = self.process.stdout.readline()
                if line:
                    self.output_signal.emit(line)
                    # 检查是否包含JSON报告路径
                    path_match = JSON_REPORT_PATH_PATTERN.search(line)
                    if path_match:
                        self.json_report_path = path_match.group(1)
            # 处理剩余输出
            remaining = self.process.stdout.read()
            if remaining:
                self.output_signal.emit(remaining)
        except Exception as e:
            self.output_signal.emit(f"[Ling][ERR]: {str(e)}")
        finally:
            # 将JSON报告路径传递给主线程
            self.finish_signal.emit(self.json_report_path)

    def stop(self):
        # 标记线程结束，并尽力终止子进程
        self.running = False
        try:
            if self.process is not None and self.process.poll() is None:
                try:
                    self.process.terminate()
                except Exception:
                    pass
                # 等待短暂时间，若仍未退出则强制杀死
                try:
                    import time
                    for _ in range(10):
                        if self.process.poll() is not None:
                            break
                        time.sleep(0.1)
                    if self.process.poll() is None:
                        self.process.kill()
                except Exception:
                    pass
        except Exception:
            pass


class VulnerabilityDetailWidget(QWidget):
    """漏洞详情展示组件"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        # 创建标签页
        self.tabs = QTabWidget()
        # 基本信息标签页
        self.basic_info = TextEdit()
        self.basic_info.setReadOnly(True)
        self.tabs.addTab(self.basic_info, "基本信息")
        # 验证步骤标签页
        self.verification_steps = TreeWidget()
        self.verification_steps.setHeaderLabel("验证步骤")
        self.tabs.addTab(self.verification_steps, "验证")
        layout.addWidget(self.tabs)
        
    def update_detail(self, vuln_data):
        """更新漏洞详情"""
        # 更新各个标签页数据
        self._update_basic_info(vuln_data)
        self._update_verification_steps(vuln_data)
    
    def _update_basic_info(self, vuln_data):
        """更新基本信息标签页"""
        basic_text = ""
        basic_text += f"主机名: {vuln_data.get('hostname', '未知')}\n"
        basic_text += f"URL: {vuln_data.get('url', '未知')}\n"
        basic_text = f"漏洞名称: {vuln_data.get('name', '未知')}\n"
        basic_text += f"漏洞类型: {vuln_data.get('vultype', '未知')}\n"
        basic_text += f"风险等级: {vuln_data.get('risk', '未知')}\n"
        basic_text += f"描述: {vuln_data.get('desc', '无')}\n"
        basic_text += f"发现时间: {vuln_data.get('createtime', '未知')}\n"
        self.basic_info.setText(basic_text)
    
    def _update_verification_steps(self, vuln_data):
        """验证步骤标签页"""
        self.verification_steps.clear()
        # 添加验证信息
        show_info = vuln_data.get('show', {})
        if show_info:
            verify_item = QTreeWidgetItem(["验证信息"])
            for key, value in show_info.items():
                verify_item.addChild(QTreeWidgetItem([f"{key}: {value}"]))
            self.verification_steps.addTopLevelItem(verify_item)
        
        # 添加漏洞详情
        detail_info = vuln_data.get('detail', {})
        if detail_info:
            # 处理请求详情
            detail_item = QTreeWidgetItem(["漏洞详情"])
            for key, value in detail_info.items():
                if isinstance(value, dict):
                    # 如果值是字典，递归处理
                    sub_item = QTreeWidgetItem([key])
                    for sub_key, sub_value in value.items():
                        sub_item.addChild(QTreeWidgetItem([f"{sub_key}: {sub_value}"]))
                    detail_item.addChild(sub_item)
                else:
                    # 如果值是简单类型，直接添加
                    detail_item.addChild(QTreeWidgetItem([f"{key}: {value}"]))
            self.verification_steps.addTopLevelItem(detail_item)
    

class Z0ScanGUI(FluentWindow):
    """z0scan 主界面"""
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(get_resource_path('doc/ling.png')))
        self.scan_thread = None
        self.vulnerabilities = []  # 存储发现的漏洞
        self.plugin_info_cache = {}  # 插件信息缓存
        self.selected_risks = [0, 1, 2, 3]  # 默认选择所有风险等级
        # 确定scanner目录路径
        self.scanner_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanners")
        if not os.path.exists(self.scanner_dir):
            self.scanner_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanners")
        self.init_ui()
        
    def init_ui(self):
        # 设置窗口基本属性
        self.setWindowTitle("Ling - Z0GUI漏洞扫描工具")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 600)
        # 设置字体
        font = QFont("SimHei", 9)
        self.setFont(font)
        # 应用 Ling 主题设置
        try:
            import json, os
            ling_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "ling_settings.json")
            if os.path.isfile(ling_cfg_path):
                with open(ling_cfg_path, "r", encoding="utf-8") as _f:
                    _cfg = json.load(_f)
                    if _cfg.get("theme", "LIGHT").upper() == "DARK":
                        setTheme(Theme.DARK)
                    else:
                        setTheme(Theme.LIGHT)
        except Exception:
            pass
        # 创建各页面并注册到 FluentWindow 侧栏
        scan_page = self.create_scan_tab()
        results_page = self.create_results_tab()
        plugins_page = self.create_plugins_tab()
        about_page = self.create_about_tab()
        # 设置页
        try:
            from interface.settings import SettingsInterface
            settings_page = SettingsInterface(self)
        except Exception:
            settings_page = QWidget()
            settings_page.setObjectName("settingsInterface")

        # 使用 FluentWindow 的侧栏导航
        from qfluentwidgets import FluentIcon
        self.addSubInterface(scan_page, FluentIcon.SEARCH, "扫描", NavigationItemPosition.TOP)
        self.addSubInterface(results_page, FluentIcon.VIEW, "扫描结果", NavigationItemPosition.TOP)
        self.addSubInterface(plugins_page, FluentIcon.APPLICATION, "插件管理", NavigationItemPosition.TOP)
        self.addSubInterface(about_page, FluentIcon.INFO, "关于", NavigationItemPosition.BOTTOM)
        self.addSubInterface(settings_page, FluentIcon.SETTING, "设置", NavigationItemPosition.BOTTOM)

    def create_scan_tab(self):
        """创建扫描配置标签页"""
        scan_tab = QWidget()
        layout = QVBoxLayout(scan_tab)
        
        mode_layout = QHBoxLayout()

        # 创建按钮组实现互斥效果
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)  # 设置为互斥

        self.active_scan_radio = CheckBox("主动扫描")
        self.active_scan_radio.setChecked(True)
        self.passive_scan_radio = CheckBox("被动扫描")

        # 将复选框添加到按钮组
        self.mode_group.addButton(self.active_scan_radio, 1)
        self.mode_group.addButton(self.passive_scan_radio, 2)

        # 绑定扫描模式切换事件
        self.active_scan_radio.toggled.connect(self.toggle_scan_mode)
        self.passive_scan_radio.toggled.connect(self.toggle_scan_mode)

        mode_layout.addWidget(self.active_scan_radio)
        mode_layout.addWidget(self.passive_scan_radio)
        mode_layout.addStretch()
        
        # 顶部配置区域
        config_group = QGroupBox("扫描配置")
        config_layout = QFormLayout()
        
        # 目标输入（主动扫描）
        self.target_input = LineEdit()
        self.target_input.setPlaceholderText("例如: https://example.com 或从文件导入: urls.txt")
        config_layout.addRow("目标URL/文件:", self.target_input)
        
        # 代理设置（被动扫描）
        self.proxy_input = LineEdit()
        self.proxy_input.setText("127.0.0.1:5920")
        self.proxy_input.setPlaceholderText("例如: 127.0.0.1:5920")
        self.proxy_input.setEnabled(False)  # 默认隐藏，被动模式下显示
        config_layout.addRow("被动服务地址(-s):", self.proxy_input)
        
        # 扫描级别选择
        self.level_combo = ComboBox()
        self.level_combo.addItems(["0 (静态分析)", "1 (基础)", "2 (中等)", "3 (深入)"])
        config_layout.addRow("扫描级别:", self.level_combo)
        
        # 风险等级选择
        risk_layout = QHBoxLayout()
        self.risk_display = LineEdit()
        self.risk_display.setText("0,1,2,3")
        self.risk_display.setReadOnly(True)
        self.risk_button = PushButton("选择风险等级")
        self.risk_button.clicked.connect(self.open_risk_dialog)
        risk_layout.addWidget(self.risk_display)
        risk_layout.addWidget(self.risk_button)
        config_layout.addRow("风险等级:", risk_layout)
        
        # 线程数设置
        self.threads_input = LineEdit()
        self.threads_input.setText("10")
        config_layout.addRow("线程数:", self.threads_input)
        
        # 请求代理(-p)
        self.request_proxy_input = LineEdit()
        self.request_proxy_input.setPlaceholderText("http://127.0.0.1:8080 或 proxy.txt")
        config_layout.addRow("请求代理(-p):", self.request_proxy_input)

        # 超时(--timeout)
        self.timeout_input = LineEdit()
        self.timeout_input.setPlaceholderText("例如: 15")
        config_layout.addRow("超时秒数(--timeout):", self.timeout_input)

        # 控制台端口(-c)
        self.console_port_input = LineEdit()
        self.console_port_input.setPlaceholderText("留空使用默认")
        config_layout.addRow("控制台端口(-c):", self.console_port_input)

        # 插件线程(-pt)
        self.plugin_threads_input = LineEdit()
        self.plugin_threads_input.setPlaceholderText("例如: 5")
        config_layout.addRow("插件线程(-pt):", self.plugin_threads_input)

        # 输出选项
        self.html_check = CheckBox("生成HTML报告(--html)")
        self.json_path_input = LineEdit()
        self.json_path_input.setPlaceholderText("自定义JSON输出路径 (留空使用默认)")
        config_layout.addRow("HTML输出:", self.html_check)
        config_layout.addRow("JSON路径(--json):", self.json_path_input)

        # 连接/Redis
        self.reverse_client_check = CheckBox("连接反连服务器(-R)")
        self.redis_client_input = LineEdit()
        self.redis_client_input.setPlaceholderText("password@host:port:db")
        config_layout.addRow("Redis客户端(-Rc):", self.redis_client_input)

        self.redis_server_input = LineEdit()
        self.redis_server_input.setPlaceholderText("password@host:port:db")
        config_layout.addRow("Redis服务端(-Rs):", self.redis_server_input)

        self.redis_clean_check = CheckBox("清理Redis(--redis-clean)")
        config_layout.addRow("Redis清理:", self.redis_clean_check)

        # 扫描Cookie
        self.scan_cookie_check = CheckBox("扫描Cookie(-sc)")
        config_layout.addRow("Cookie:", self.scan_cookie_check)

        # 仅加载插件
        self.enable_scanners_input = LineEdit()
        self.enable_scanners_input.setPlaceholderText("仅加载的插件名, 逗号分隔")
        config_layout.addRow("仅加载(--enable):", self.enable_scanners_input)

        config_group.setLayout(config_layout)
        
        # 高级选项
        advanced_group = QGroupBox("高级选项")
        advanced_layout = QVBoxLayout()
        
        options_layout = QHBoxLayout()
        
        # 左侧选项
        left_layout = QVBoxLayout()
        self.random_agent_check = CheckBox("使用随机User-Agent")
        self.ignore_waf_check = CheckBox("忽略WAF检测")
        
        left_layout.addWidget(self.random_agent_check)
        left_layout.addWidget(self.ignore_waf_check)
        
        # 右侧选项
        right_layout = QVBoxLayout()
        self.fingerprint_check = CheckBox("忽略指纹要素")
        self.ipv6_check = CheckBox("启用IPv6支持")
        
        right_layout.addWidget(self.fingerprint_check)
        right_layout.addWidget(self.ipv6_check)
        
        options_layout.addLayout(left_layout)
        options_layout.addLayout(right_layout)
        advanced_group.setLayout(options_layout)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        self.start_btn = PrimaryPushButton("开始扫描")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = PushButton("停止扫描")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        
        # 扫描输出区域
        output_group = QGroupBox("扫描输出")
        output_layout = QVBoxLayout()
        
        self.scan_output = TextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setStyleSheet("background-color: #1E1E1E; color: #FFFFFF;")
        
        # 进度条
        self.progress_bar = ProgressBar()
        self.progress_bar.setRange(0, 0)  # 不确定进度
        self.progress_bar.setVisible(False)
        
        output_layout.addWidget(self.progress_bar)
        output_layout.addWidget(self.scan_output)
        output_group.setLayout(output_layout)
        
        # 组装扫描标签页
        layout.addLayout(mode_layout)
        layout.addWidget(config_group)
        layout.addWidget(advanced_group)
        layout.addLayout(btn_layout)
        layout.addWidget(output_group)
        
        # 使用可滚动容器包裹页面，允许上下滚动
        try:
            from qfluentwidgets import SmoothScrollArea as _ScrollArea
        except Exception:
            try:
                from qfluentwidgets import ScrollArea as _ScrollArea
            except Exception:
                from PyQt5.QtWidgets import QScrollArea as _ScrollArea

        scroll_area = _ScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(scan_tab)
        scroll_area.setObjectName("scanInterface")
        return scroll_area

    def open_risk_dialog(self):
        """打开风险等级选择对话框"""
        dialog = RiskSelectionDialog(self)
        # 设置当前选中状态
        for level, cb in dialog.risk_options.items():
            cb.setChecked(level in self.selected_risks)
            
        if dialog.exec_():
            self.selected_risks = dialog.get_selected_risks()
            # 更新显示
            self.risk_display.setText(",".join(map(str, self.selected_risks)))

    def create_results_tab(self):
        """创建扫描结果标签页"""
        results_tab = QWidget()
        layout = QVBoxLayout(results_tab)
        
        # 结果过滤
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("风险等级过滤:"))
        self.risk_filter = ComboBox()
        self.risk_filter.addItems(["全部", "0 (信息)", "1 (低)", "2 (中)", "3 (高)"])
        self.risk_filter.currentIndexChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.risk_filter)
        
        filter_layout.addWidget(QLabel("漏洞类型过滤:"))
        self.type_filter = ComboBox()
        self.type_filter.addItems(["全部", "SQLi", "SSTi", "CSRF", "SSRF", "XSS", "命令注入", "路径遍历", "敏感信息泄露", "其他"])
        self.type_filter.currentIndexChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.type_filter)
        
        filter_layout.addStretch()
        
        # 结果列表和详情分割
        splitter = QSplitter(Qt.Vertical)
        
        # 结果列表
        self.results_list = TreeWidget()
        self.results_list.setHeaderLabels(["漏洞名称", "URL", "风险等级", "发现时间"])
        self.results_list.header().setSectionResizeMode(QHeaderView.Stretch)
        self.results_list.itemClicked.connect(self.show_vulnerability_detail)
        
        # 结果详情
        self.vuln_detail = VulnerabilityDetailWidget()
        
        splitter.addWidget(self.results_list)
        splitter.addWidget(self.vuln_detail)
        splitter.setSizes([200, 600])
        
        # 结果操作按钮
        btn_layout = QHBoxLayout()
        self.save_result_btn = PushButton("保存结果")
        self.save_result_btn.clicked.connect(self.save_results)
        self.export_html_btn = PushButton("导出HTML报告")
        self.export_html_btn.clicked.connect(self.export_html)
        self.clear_results_btn = PushButton("清空结果")
        self.clear_results_btn.clicked.connect(self.clear_results)
        
        btn_layout.addWidget(self.save_result_btn)
        btn_layout.addWidget(self.export_html_btn)
        btn_layout.addWidget(self.clear_results_btn)
        
        layout.addLayout(filter_layout)
        layout.addLayout(btn_layout)
        layout.addWidget(splitter)
        
        results_tab.setObjectName("resultsInterface")
        return results_tab

    def create_plugins_tab(self):
        """创建插件管理标签页（按分类展示）"""
        plugins_tab = QWidget()
        layout = QVBoxLayout(plugins_tab)
        
        # 插件过滤
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("风险等级过滤:"))
        self.plugin_risk_filter = ComboBox()
        self.plugin_risk_filter.addItems(["全部", "0 (信息)", "1 (低)", "2 (中)", "3 (高)"])
        self.plugin_risk_filter.currentIndexChanged.connect(self.filter_plugins)
        filter_layout.addWidget(self.plugin_risk_filter)
        
        filter_layout.addWidget(QLabel("搜索:"))
        self.plugin_search = LineEdit()
        self.plugin_search.setPlaceholderText("输入插件名称或描述关键词")
        self.plugin_search.textChanged.connect(self.filter_plugins)
        filter_layout.addWidget(self.plugin_search)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # 创建分类标签页
        self.plugins_tabs = QTabWidget()
        
        # perpage 插件
        self.perpage_plugins = ListWidget()
        self.perpage_plugins.setAlternatingRowColors(True)
        self.perpage_plugins.setSelectionMode(QListWidget.ExtendedSelection)
        self.plugins_tabs.addTab(self.perpage_plugins, "PerPage")
        
        # perdir 插件
        self.perdir_plugins = ListWidget()
        self.perdir_plugins.setAlternatingRowColors(True)
        self.perdir_plugins.setSelectionMode(QListWidget.ExtendedSelection)
        self.plugins_tabs.addTab(self.perdir_plugins, "PerDir")
        
        # PerDomain 插件
        self.perdomain_plugins = ListWidget()
        self.perdomain_plugins.setAlternatingRowColors(True)
        self.perdomain_plugins.setSelectionMode(QListWidget.ExtendedSelection)
        self.plugins_tabs.addTab(self.perdomain_plugins, "PerDomain")
        
        # PerHost 插件 - 新增的PerHost类型支持
        self.perhost_plugins = ListWidget()
        self.perhost_plugins.setAlternatingRowColors(True)
        self.perhost_plugins.setSelectionMode(QListWidget.ExtendedSelection)
        self.plugins_tabs.addTab(self.perhost_plugins, "PerHost")
        
        # 加载插件列表（从目录扫描获取）
        self.load_plugins()
        
        # 插件操作按钮
        btn_layout = QHBoxLayout()
        self.enable_all_btn = PushButton("全部启用")
        self.enable_all_btn.clicked.connect(lambda: self.set_all_plugins(True))
        self.disable_all_btn = PushButton("全部禁用")
        self.disable_all_btn.clicked.connect(lambda: self.set_all_plugins(False))
        self.refresh_plugins_btn = PushButton("刷新插件列表")
        self.refresh_plugins_btn.clicked.connect(self.refresh_plugins)
        
        btn_layout.addWidget(self.enable_all_btn)
        btn_layout.addWidget(self.disable_all_btn)
        btn_layout.addWidget(self.refresh_plugins_btn)
        
        layout.addLayout(btn_layout)
        layout.addWidget(self.plugins_tabs)
        
        # 插件详情
        self.plugin_detail = TextEdit()
        self.plugin_detail.setReadOnly(True)
        self.plugin_detail.setMaximumHeight(100)
        layout.addWidget(QLabel("插件详情:"))
        layout.addWidget(self.plugin_detail)
        
        # 绑定插件选择事件
        self.perpage_plugins.itemClicked.connect(self.show_plugin_detail)
        self.perdir_plugins.itemClicked.connect(self.show_plugin_detail)
        self.perdomain_plugins.itemClicked.connect(self.show_plugin_detail)
        self.perhost_plugins.itemClicked.connect(self.show_plugin_detail)  # 绑定PerHost插件点击事件
        
        plugins_tab.setObjectName("pluginsInterface")
        return plugins_tab

    def create_about_tab(self):
        """创建关于标签页"""
        about_tab = QWidget()
        layout = QVBoxLayout(about_tab)
        # 使用AboutDialog的内容创建标签页
        about_text = TextEdit()
        about_text.setReadOnly(True)
        about_text.setStyleSheet("background-color: transparent; border: none;")
        about_text.setHtml(INFO)
        layout.addWidget(about_text)
        about_tab.setObjectName("aboutInterface")
        return about_tab

    # 辅助方法
    def toggle_scan_mode(self):
        """切换主动/被动扫描模式"""
        is_active = self.active_scan_radio.isChecked()
        self.target_input.setEnabled(is_active)
        self.proxy_input.setEnabled(not is_active)

    def choose_path(self, line_edit, title):
        """选择路径"""
        path = QFileDialog.getExistingDirectory(self, title, os.getcwd())
        if path:
            line_edit.setText(path)

    def load_plugins(self):
        """从scanner目录下的perpage、perdir、PerDomain和PerHost文件夹加载插件列表"""
        # 清空现有列表
        self.perpage_plugins.clear()
        self.perdir_plugins.clear()
        self.perdomain_plugins.clear()
        self.perhost_plugins.clear()  # 清空PerHost列表
        self.plugin_info_cache.clear()
        
        # 插件类型与目录的映射 - 添加PerHost支持
        plugin_types = {
            "PerPage": self.perpage_plugins,
            "PerDir": self.perdir_plugins,
            "PerDomain": self.perdomain_plugins,
            "PerHost": self.perhost_plugins  # 添加PerHost映射
        }
        
        # 遍历每种插件类型对应的目录
        for plugin_type, list_widget in plugin_types.items():
            plugin_dir = os.path.join(self.scanner_dir, plugin_type)
            # 检查目录是否存在
            if not os.path.exists(plugin_dir) or not os.path.isdir(plugin_dir):
                print(f"警告: {plugin_type} 目录不存在: {plugin_dir}")
                continue
                
            # 遍历目录中的所有插件
            for filename in os.listdir(plugin_dir):
                if filename.endswith(".py") and not filename.startswith("__"):
                    plugin_path = os.path.join(plugin_dir, filename)
                    plugin_info = self.get_plugin_info(plugin_path, filename)
                    if plugin_info:
                        # 缓存插件信息
                        self.plugin_info_cache[plugin_info['name']] = plugin_info
                        # 创建列表项
                        risk_text = f"RISK: {plugin_info['risk']}"
                        item_text = f"{plugin_info['name']} - {plugin_info['desc']} ({risk_text})"
                        item = QListWidgetItem(item_text)
                        item.setCheckState(Qt.Checked)
                        item.setData(Qt.UserRole, plugin_info['name'])
                        # 根据风险等级设置颜色
                        risk = plugin_info['risk']
                        if risk == 3:
                            item.setForeground(QColor(255, 0, 0))  # 高风险-红色
                        elif risk == 2:
                            item.setForeground(QColor(255, 165, 0))  # 中风险-橙色
                        elif risk == 1:
                            item.setForeground(QColor(255, 255, 0))  # 低风险-黄色
                        else:
                            item.setForeground(QColor(0, 255, 0))  # 信息-绿色
                        list_widget.addItem(item)

    def get_plugin_info(self, plugin_path, filename):
        """通过正则表达式从插件文件中提取信息"""
        try:
            # 读取文件内容
            with open(plugin_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # 使用正则提取信息
            name = PLUGIN_INFO_PATTERNS['name'].search(content)
            desc = PLUGIN_INFO_PATTERNS['desc'].search(content)
            version = PLUGIN_INFO_PATTERNS['version'].search(content)
            risk = PLUGIN_INFO_PATTERNS['risk'].search(content)
            # 处理提取结果
            plugin_name = name.group(1) if name else os.path.splitext(filename)[0]
            plugin_desc = desc.group(1) if desc else "无描述"
            plugin_version = version.group(1) if version else "未知版本"
            plugin_risk = int(risk.group(1)) if risk else 0
            return {
                'name': plugin_name,
                'desc': plugin_desc,
                'version': plugin_version,
                'risk': plugin_risk,
                'path': plugin_path
            }
        except Exception as e:
            print(f"获取插件信息失败 {plugin_path}: {str(e)}")
            return None

    def show_plugin_detail(self, item):
        """显示插件详情"""
        plugin_name = item.data(Qt.UserRole)
        if plugin_name in self.plugin_info_cache:
            info = self.plugin_info_cache[plugin_name]
            detail_text = f"名称: {info['name']}\n"
            detail_text += f"描述: {info['desc']}\n"
            detail_text += f"版本: {info['version']}\n"
            detail_text += f"风险等级: {info['risk']}\n"
            detail_text += f"路径: {info['path']}"
            self.plugin_detail.setText(detail_text)

    def filter_plugins(self):
        """过滤插件列表"""
        risk_filter = self.plugin_risk_filter.currentIndex() - 1  # -1表示全部
        search_text = self.plugin_search.text().lower()
        
        # 对当前活动的插件标签页进行过滤
        current_tab = self.plugins_tabs.currentWidget()
        for i in range(current_tab.count()):
            item = current_tab.item(i)
            plugin_name = item.data(Qt.UserRole)
            
            # 风险过滤
            if risk_filter != -1:
                plugin_info = self.plugin_info_cache.get(plugin_name)
                if not plugin_info or plugin_info['risk'] != risk_filter:
                    item.setHidden(True)
                    continue
            
            # 文本搜索过滤
            if search_text and search_text not in item.text().lower():
                item.setHidden(True)
                continue
                
            item.setHidden(False)

    def get_disabled_plugins(self):
        """获取禁用的插件列表"""
        disabled = []
        
        # 检查所有标签页的插件（包括PerHost）
        for list_widget in [self.perpage_plugins, self.perdir_plugins, 
                          self.perdomain_plugins, self.perhost_plugins]:
            for i in range(list_widget.count()):
                item = list_widget.item(i)
                if not item.isHidden() and item.checkState() == Qt.Unchecked:
                    disabled.append(item.data(Qt.UserRole))
                    
        return disabled

    def set_all_plugins(self, enabled):
        """设置所有插件的启用状态"""
        state = Qt.Checked if enabled else Qt.Unchecked
        current_tab = self.plugins_tabs.currentWidget()
        
        for i in range(current_tab.count()):
            item = current_tab.item(i)
            if not item.isHidden():
                item.setCheckState(state)

    def refresh_plugins(self):
        """刷新插件列表"""
        self.load_plugins()
        InfoBar.success(title="提示", content="插件列表已刷新", position=InfoBarPosition.TOP, parent=self, duration=2000)

    def start_scan(self):
        """开始扫描"""
        current_dir = os.getcwd()
        # 读取 Ling 设置的可执行路径
        exe_override = ""
        try:
            import json as _json
            ling_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "ling_settings.json")
            if os.path.isfile(ling_cfg_path):
                with open(ling_cfg_path, "r", encoding="utf-8") as _f:
                    _cfg = _json.load(_f)
                    exe_override = _cfg.get("exe_path", "").strip()
        except Exception:
            pass

        # 根据平台确定可能的可执行文件
        if sys.platform.startswith('win'):
            default_name = "z0.exe"
        else:
            default_name = "z0"

        candidates = []
        if exe_override:
            candidates.append(exe_override)
        candidates.append(os.path.join(current_dir, default_name))
        candidates.append(os.path.join(current_dir, "z0.py"))

        # 选择命令
        if candidates and os.path.isfile(candidates[0]) and not candidates[0].endswith(".py"):
            command = f"{candidates[0]} scan"
        elif os.path.isfile(os.path.join(current_dir, default_name)):
            command = f"{os.path.join(current_dir, default_name)} scan"
        else:
            python_cmd = "python" if sys.platform.startswith('win') else "python3"
            command = f"{python_cmd} {os.path.join(current_dir, 'z0.py')} scan"
        
        # 主动/被动模式
        if self.active_scan_radio.isChecked():
            target = self.target_input.text().strip()
            if not target:
                self.scan_output.append("请输入目标URL或文件")
                return
            if target.split(".")[-1] == "txt":
                command += f" -f {target}"
            else:
                command += f" -u {target}"
        else:
            proxy = self.proxy_input.text().strip()
            if not proxy:
                self.scan_output.append("请输入代理端口")
                return
            command += f" -s {proxy}"
        
        # 添加扫描级别
        level = self.level_combo.currentText()[0]
        command += f" --level {level}"
        
        # 添加风险等级 - 支持多个风险等级
        if self.selected_risks:
            command += f" --risk {','.join(map(str, self.selected_risks))}"
        
        # 添加线程数
        threads = self.threads_input.text().strip()
        if threads:
            command += f" --threads {threads}"
        
        # 添加高级选项
        if self.random_agent_check.isChecked():
            command += " --random-agent"
        
        if self.ignore_waf_check.isChecked():
            command += " --ignore-waf"
        
        '''
        if self.ipv6_check.isChecked():
            command += " --ipv6"
        '''
        
        if self.fingerprint_check.isChecked():
            command += " --ignore-fingerprint"

        # 请求代理(-p)
        p = self.request_proxy_input.text().strip()
        if p:
            command += f" -p {p}"

        # 超时(--timeout)
        timeout = self.timeout_input.text().strip()
        if timeout.isdigit():
            command += f" --timeout {timeout}"

        # 控制台端口(-c)
        cport = self.console_port_input.text().strip()
        if cport:
            command += f" -c {cport}"

        # 插件线程(-pt)
        pt = self.plugin_threads_input.text().strip()
        if pt.isdigit():
            command += f" -pt {pt}"

        # 输出(--html/--json)
        if self.html_check.isChecked():
            command += " --html"
        json_path = self.json_path_input.text().strip()
        if json_path:
            command += f" --json {json_path}"

        # 扫描Cookie(-sc)
        if self.scan_cookie_check.isChecked():
            command += " -sc"

        # 连接/Redis
        if self.reverse_client_check.isChecked():
            command += " -R"
        rc = self.redis_client_input.text().strip()
        if rc:
            command += f" -Rc {rc}"
        rs = self.redis_server_input.text().strip()
        if rs:
            command += f" -Rs {rs}"
        if self.redis_clean_check.isChecked():
            command += " --redis-clean"

        # 仅加载插件(--enable)
        enable_list = self.enable_scanners_input.text().strip()
        if enable_list:
            command += f" --enable {enable_list}"
        
        # 添加禁用的插件
        disabled_plugins = self.get_disabled_plugins()
        if disabled_plugins:
            command += f" --disable {','.join(disabled_plugins)}"
        
        # 显示命令并开始扫描
        self.scan_output.append(f"[{QDateTime.currentDateTime().toString()}] 扫描命令: {command}")
        self.scan_output.append(f"[{QDateTime.currentDateTime().toString()}] 开始扫描...\n")
        
        # 启动扫描线程
        self.scan_thread = ScanThread(command)
        self.scan_thread.output_signal.connect(self.update_output)
        self.scan_thread.finish_signal.connect(self.scan_finished)
        self.scan_thread.start()
        
        # 更新UI状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        InfoBar.info(title="提示", content="扫描中...", position=InfoBarPosition.TOP, parent=self, duration=2000)

    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_output.append(f"\n[{QDateTime.currentDateTime().toString()}] 扫描已停止")
            self.scan_finished(None)

    def scan_finished(self, json_report_path):
        """扫描完成回调，处理JSON报告"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        if json_report_path:
            InfoBar.info(title="提示", content=f"扫描结束，正在处理报告: {json_report_path}", position=InfoBarPosition.TOP, parent=self, duration=3000)
            self.process_json_report(json_report_path)
        else:
            InfoBar.warning(title="提示", content="扫描结束，未找到JSON报告", position=InfoBarPosition.TOP, parent=self, duration=3000)
        self.scan_output.append(f"\n[{QDateTime.currentDateTime().toString()}] 扫描完成")

    def process_json_report(self, report_path):
        """处理JSON报告文件，提取漏洞信息"""
        try:
            # 检查文件是否存在
            if not os.path.exists(report_path):
                self.scan_output.append(f"错误: 报告文件不存在 - {report_path}")
                return    
            # 读取并解析JSON文件
            with open(report_path, 'r', encoding='utf-8') as f:
                try:
                    vuln_list = json.load(f)
                except json.JSONDecodeError:
                    self.scan_output.append(f"错误: 无法解析JSON报告 - {report_path}")
                    return
            # 清空现有漏洞列表
            self.vulnerabilities = []
            self.results_list.clear()
            # 添加所有漏洞到结果列表
            for vuln in vuln_list:
                self.add_vulnerability(vuln)
            self.scan_output.append(f"成功加载 {len(vuln_list)} 个漏洞信息")
            InfoBar.success(title="成功", content=f"扫描完成，发现 {len(vuln_list)} 个漏洞", position=InfoBarPosition.TOP, parent=self, duration=3000)
        except Exception as e:
            self.scan_output.append(f"处理报告时出错: {str(e)}")
            InfoBar.error(title="错误", content="处理报告时出错", position=InfoBarPosition.TOP, parent=self, duration=3000)

    def update_output(self, text):
        """更新输出内容"""
        self.scan_output.append(text.strip())
        # 滚动到底部
        self.scan_output.moveCursor(self.scan_output.textCursor().End)

    def add_vulnerability(self, vuln_data):
        """添加漏洞到结果列表"""
        self.vulnerabilities.append(vuln_data)
        # 创建列表项
        item = QTreeWidgetItem([
            vuln_data.get('name', '未知'),
            vuln_data.get('url', '未知'),
            str(vuln_data.get('risk', 0)),
            vuln_data.get('createtime', '')
        ])
        # 根据风险等级设置颜色
        risk = vuln_data.get('risk', 0)
        if risk == 3:
            item.setForeground(2, QColor(255, 0, 0))  # 高风险-红色
        elif risk == 2:
            item.setForeground(2, QColor(255, 165, 0))  # 中风险-橙色
        elif risk == 1:
            item.setForeground(2, QColor(255, 255, 0))  # 低风险-黄色
        else:
            item.setForeground(2, QColor(0, 255, 0))  # 信息-绿色
        item.setData(0, Qt.UserRole, vuln_data)  # 存储完整数据
        self.results_list.addTopLevelItem(item)

    def show_vulnerability_detail(self, item):
        """显示漏洞详情"""
        vuln_data = item.data(0, Qt.UserRole)
        if vuln_data:
            self.vuln_detail.update_detail(vuln_data)

    def filter_vulnerabilities(self):
        """根据风险等级和类型过滤漏洞"""
        risk_filter = self.risk_filter.currentIndex() - 1  # 转换为0-3或-1(全部)
        type_filter = self.type_filter.currentText()
        # 保存当前选中项
        current_item = self.results_list.currentItem()
        current_data = current_item.data(0, Qt.UserRole) if current_item else None
        # 清除现有列表
        self.results_list.clear()
        # 重新添加符合条件的漏洞
        for vuln in self.vulnerabilities:
            # 风险过滤
            if risk_filter != -1 and vuln.get('risk') != risk_filter:
                continue
                
            # 类型过滤
            if type_filter != "全部":
                vuln_type = vuln.get('vultype', '').lower()
                if (type_filter == "XSS" and "xss" not in vuln_type) or \
                   (type_filter == "命令注入" and "cmdi" not in vuln_type) or \
                   (type_filter == "路径遍历" and "trave" not in vuln_type) or \
                   (type_filter == "敏感信息泄露" and "sensi" not in vuln_type):
                    continue
                
            item = QTreeWidgetItem([
                vuln.get('name', '未知'),
                vuln.get('url', '未知'),
                str(vuln.get('risk', 0)),
                vuln.get('createtime', '')
            ])
            
            # 设置颜色
            risk = vuln.get('risk', 0)
            if risk == 3:
                item.setForeground(2, QColor(255, 0, 0))
            elif risk == 2:
                item.setForeground(2, QColor(255, 165, 0))
            elif risk == 1:
                item.setForeground(2, QColor(255, 255, 0))
            else:
                item.setForeground(2, QColor(0, 255, 0))
                
            item.setData(0, Qt.UserRole, vuln)
            self.results_list.addTopLevelItem(item)
            
            # 重新选中之前的项
            if current_data and vuln == current_data:
                self.results_list.setCurrentItem(item)

    def save_results(self):
        """保存结果"""
        if not self.vulnerabilities:
            InfoBar.warning(title="提示", content="没有结果可保存", position=InfoBarPosition.TOP, parent=self, duration=3000)
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "保存结果", os.getcwd(), "JSON文件 (*.json);;文本文件 (*.txt)"
        )
        if filename:
            try:
                import json
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=2)
                InfoBar.success(title="成功", content=f"结果已保存到 {filename}", position=InfoBarPosition.TOP, parent=self, duration=3000)
            except Exception as e:
                InfoBar.error(title="错误", content=f"保存失败: {str(e)}", position=InfoBarPosition.TOP, parent=self, duration=4000)

    def export_html(self):
        """导出HTML报告"""
        if not self.vulnerabilities:
            InfoBar.warning(title="提示", content="没有结果可导出", position=InfoBarPosition.TOP, parent=self, duration=3000)
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "导出HTML报告", os.getcwd(), "HTML文件 (*.html)"
        )
        if filename:
            try:
                # 生成HTML报告
                html = "<html><head><meta charset='utf-8'><title>z0scan 扫描报告</title></head>"
                html += f"<body><h1>z0scan 扫描报告 - {QDateTime.currentDateTime().toString()}</h1>"
                html += f"<p>共发现 {len(self.vulnerabilities)} 个漏洞</p>"
                html += "<table border='1' cellspacing='0' cellpadding='5'>"
                html += "<tr><th>漏洞名称</th><th>URL</th><th>类型</th><th>风险等级</th><th>发现时间</th><th>描述</th></tr>"
                
                for vuln in self.vulnerabilities:
                    risk = vuln.get('risk', 0)
                    risk_color = "green" if risk == 0 else "yellow" if risk == 1 else "orange" if risk == 2 else "red"
                    html += f"<tr><td>{vuln.get('name')}</td><td>{vuln.get('url')}</td><td>{vuln.get('vultype')}</td>"
                    html += f"<td style='color:{risk_color}'>{risk}</td><td>{vuln.get('createtime')}</td><td>{vuln.get('desc')}</td></tr>"
                
                html += "</table></body></html>"
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html)
                InfoBar.success(title="成功", content=f"HTML报告已导出到 {filename}", position=InfoBarPosition.TOP, parent=self, duration=3000)
            except Exception as e:
                InfoBar.error(title="错误", content=f"导出失败: {str(e)}", position=InfoBarPosition.TOP, parent=self, duration=4000)

    def clear_results(self):
        """清空结果"""
        if QMessageBox.question(self, "确认", "确定要清空所有结果吗?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            self.results_list.clear()
            self.vulnerabilities = []
            self.vuln_detail.update_detail({})

    def closeEvent(self, e):
        """拦截窗口关闭：如有扫描进行，先询问，确认后停止扫描再退出"""
        running = False
        try:
            running = self.scan_thread is not None and self.scan_thread.isRunning()
        except Exception:
            running = False

        if running:
            try:
                # 优先使用 QFluentWidgets 的 MessageBox
                from qfluentwidgets import MessageBox
                box = MessageBox("正在扫描", "当前有扫描正在进行，确定要停止并退出吗？", self)
                try:
                    box.yesButton.setText("退出并停止")
                    box.cancelButton.setText("取消")
                except Exception:
                    pass
                if box.exec():
                    try:
                        self.stop_scan()
                    except Exception:
                        pass
                    e.accept()
                else:
                    e.ignore()
                    try:
                        InfoBar.info(title="已取消", content="已取消退出操作", position=InfoBarPosition.TOP, parent=self, duration=2000)
                    except Exception:
                        pass
            except Exception:
                # 回退到原生对话框
                reply = QMessageBox.question(self, "正在扫描", "当前有扫描正在进行，确定要停止并退出吗？", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    try:
                        self.stop_scan()
                    except Exception:
                        pass
                    e.accept()
                else:
                    e.ignore()
        else:
            e.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 创建并展示启动页（SplashScreen），包含不确定进度条（稳定版：先 Splash，后主窗体，延时关闭，不阻塞UI）
    try:
        icon = QIcon(get_resource_path('doc/ling.png')) if os.path.exists(get_resource_path('doc/ling.png')) else QIcon()
        splash = SplashScreen(icon)
        try:
            # 去除系统标题栏，避免与组件样式重复的最小化/关闭按钮
            splash.setWindowFlag(Qt.FramelessWindowHint, True)
            splash.setAttribute(Qt.WA_TranslucentBackground, True)
        except Exception:
            pass
        try:
            splash.setTitle("正在启动 Ling · Z0Scan")
        except Exception:
            pass
        # 添加不确定进度条
        from PyQt5.QtWidgets import QVBoxLayout
        bar = IndeterminateProgressBar(splash)
        bar.setFixedHeight(12)
        lay = QVBoxLayout(splash)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(bar)
        splash.resize(520, 320)
        splash.show()

        # 创建主窗体（在 Splash 显示后创建）
        window = Z0ScanGUI()
        # 将 Splash 的大小与位置同步为与主窗口一致
        try:
            splash.setGeometry(window.geometry())
            splash.raise_()
        except Exception:
            pass

        # 3 秒后关闭 Splash 并显示主窗体（避免 sleep 阻塞）
        def _finish():
            try:
                splash.close()
            except Exception:
                pass
            window.show()

        QTimer.singleShot(3000, _finish)
    except Exception:
        # 回退：若 SplashScreen 创建失败，直接进入主窗体
        window = Z0ScanGUI()
        window.show()

    # 显示欢迎 InfoBar，2 秒后自动消失（Toast 替代）
    try:
        import random
        phrases = [
            "解铃还须系铃人",
            "道路千万条，安全第一条",
            "安全即责任，细节见真章",
            "愿有人问粥可温，愿有人与共黄昏",
            "人生苦短，我用 Ling",
            "发愤识遍天下洞，立志夺尽人间旗",
        ]
        msg = random.choice(phrases)
        InfoBar.success(
            title="欢迎",
            content=msg,
            position=InfoBarPosition.TOP,
            parent=window,
            duration=3000
        )
    except Exception:
        pass

    sys.exit(app.exec_())