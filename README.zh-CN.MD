![z0scan](https://socialify.git.ci/JiuZero/z0scan/image?description=1&font=Raleway&language=1&logo=https%3A%2F%2Fraw.githubusercontent.com%2FJiuZero%2Fz0scan%2Frefs%2Fheads%2Fmain%2Fdoc%2Flogo.png&owner=1&pattern=Solid&theme=Auto)

<h4 align="center" dir="auto">
  中文 | <a href="https://github.com/JiuZero/z0scan/blob/master/README.MD">英文</a> | <a href="https://jiuzero.github.io/tags/z0scan/">文档</a>
</p>

<p align="center">
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white">
  </a>
  <a href="https://github.com/JiuZero/z0scan">
    <img src="https://img.shields.io/github/last-commit/JiuZero/z0scan?style=flat&logo=github">
  </a>
  <a href="https://github.com/JiuZero/z0scan">
    <img src="https://img.shields.io/github/stars/JiuZero/z0scan?style=flat&logo=github&color=yellow">
  </a>
  <a href="https://www.gnu.org/licenses/gpl-2.0.en.html">
    <img src="https://img.shields.io/badge/License-GPL2-red?style=flat&logo=gnu">
  </a>
</p>

## ⚠️ 免责声明

> 如您在使用本项目及包含工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

> 您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

## 🌟 优势

1. WAF判断、指纹信息与插件扫描的联动
2. 能够解析Json、XML等复杂格式中的参数及伪静态参数（Beta）
3. 以SQLite3提供扫描记录等数据储存支持
4. 基于Python3开源并提供全平台支持
5. 支持IPV6解析域名（Beta）
6. 交互式动态调整被动扫描参数

## 🔧 安装

### 推荐

获取发行版本（**由nuitka编译构建，速度&性能显著提升**）：[获取](https://gitee.com/JiuZero/z0scan/releases)

- 想构建适合自己环境的可执行文件？，请见：[文档](https://jiuzero.github.io/tags/z0scan/)

### 不推荐

> 自2025.7.19起已不再提交pypi更新

**pip**快捷安装
```bash
# GitHub
pip install git+https://github.com/JiuZero/z0scan
# Gitee
pip install git+https://gitee.com/JiuZero/z0scan
z0 help
```

通过**GitHub**克隆安装
```bash
git clone https://github.com/JiuZero/z0scan
cd z0scan
pip install -r requirements.txt
python3 z0.py help
```

- 部分**特殊环境安装**（如Termux），请见：[文档](https://jiuzero.github.io/tags/z0scan/)

## 🚀 使用示例

### 被动扫描

默认配置下**被动扫描**（浏览器转发流量到5920端口）
```
z0 scan -s 127.0.0.1:5920
```

![example](doc/example0.png)

常用推荐
```
z0 scan -s 127.0.0.1:5920 --risk 0,1,2,3 --level 2 --disable cmdi,unauth
```

### 主动扫描

默认配置下**主动扫描**
```
# 由Burp/Yakit发起请求流量的主动检测（推荐）
z0 scan -s 127.0.0.1:5920
```

![example](doc/example1.png)

```
# 直接检测
z0 scan -u https://example.com/?id=1
# 遍历URL列表检测
z0 scan -f urls.txt
```

![example](doc/example2.png)

- 获取更加详细的信息，请见：[文档](https://jiuzero.github.io/tags/z0scan/)

## ✨ ️插件列表

- PerFile

|插件名称|插件简述|Risk|
|:---:|:----:|:----:|
|sqli-bool|SQL布尔盲注检测|2|
|sqli-time|SQL时间盲注检测|2|
|sqli-error|SQL报错注入检测|2|
|codei-asp|Asp代码执行|3|
|codei-php|Php代码执行|3|
|cmdi|命令执行|3|
|other-objectdese|反序列参数分析|3|
|sensi-js|Js敏感信息泄露|0|
|sensi-jsonp|Jsonp敏感信息泄露|1|
|sensi-php-realpath|Php真实目录发现|0|
|redirect|重定向|1|
|sensi-webpack|webpack源码泄露|1|
|other-webdav-passive|webdav服务被动发现|1|
|xpathi-error|基于报错的XPATH注入检测|2|
|trave-path|路径穿越|2|
|sensi-backup_1|基于文件的备份文件检测|1|
|sensi-viewstate|未加密的VIEWSTATE发现|0|
|xss|基于JS语义的XSS扫描|1|
|crlf_1|CRLF漏洞检测|2|
|cors-passive|CORS漏洞检测（被动分析）|2|
|unauth|未授权访问漏洞|2|
|leakpwd-page-passive|后台登陆页弱口令|2|
|sensi-editfile|编辑器备份文件泄露|1|
|sensi-sourcecode|源码泄露|1|
|captcha-bypass|验证码绕过|0|
|sensi-retirejs|过时的JS组件检测|-1|
|ssti|SSTI漏洞检测|3|

- PerFolder

|插件名称|插件简述|Risk|
|:---:|:----:|:----:|
|sensi-backup_2|基于各级目录的备份文件扫描|1|
|trave-list_2|目录浏览|2|
|sensi-file|敏感文件泄漏（包括phpinfo，.git等）|/|
|upload-oss|OSS储存桶任意文件上传|2|
|sensi-frontpage|FrontPage 配置信息泄露|1|

- PerServer

|插件名称|插件简述|Risk|
|:---:|:----:|:----:|
|sensi-errorpage|错误页敏感信息泄露|0|
|xss-net|.NET通杀XSS|1|
|other-dns-zonetransfer|DNS域传送漏洞|1|
|xss-flash|Flash通杀XSS|1|
|other-idea-parse|Idea目录解析|1|
|other-xst|XST漏洞检测|-1|
|other-webdav-active|webdav服务发现|1|
|upload-put|基于PUT请求的任意文件上传|3|
|sensi-backup_3|基于域名的备份文件检测|1|
|cors-active|CORS漏洞检测（主动发现）|2|
|crlf_3|CRLF换行注入漏洞|2|
|other-hosti|Host头注入攻击检测|1|
|other-oss-takeover|OSS储存桶接管漏洞|3|
|sensi-iis-shortname|IIS短文件名漏洞|0|
|other-clickjacking|点击劫持漏洞|-1|
|other-baseline|服务版本泄露|-1|
|other-smuggling|请求走私漏洞|3|
|trave-list_3|目录浏览|2|

## 🔆 更新日记 & 许可

- 更新日记：[CHANGELOG](https://github.com/JiuZero/z0scan/blob/master/doc/CHANGELOG.MD)

- 未来：[TODO](https://github.com/JiuZero/z0scan/blob/master/doc/TODO.MD)

- GPL-2.0授权许可：[LICENSE](https://github.com/JiuZero/z0scan/blob/master/LICENSE)

## 📝 联系

|平台|联系|
|:---:|:----:|
|WeiXin|JiuZer1|
|QQ|1703417187|
|Email|jiuzer0@qq.com|