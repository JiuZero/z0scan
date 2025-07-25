![z0scan](https://socialify.git.ci/JiuZero/z0scan/image?description=1&font=Raleway&language=1&logo=https%3A%2F%2Fraw.githubusercontent.com%2FJiuZero%2Fz0scan%2Frefs%2Fheads%2Fmain%2Fdoc%2Flogo.png&owner=1&pattern=Solid&theme=Auto)

<h4 align="center" dir="auto">
  <a href="https://github.com/JiuZero/z0scan/blob/master/README.zh-CN.MD">Chinese</a> • English • <a href="https://jiuzero.github.io/tags/z0scan/">Documentation</a>
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

## Acknowledgments

<div><table frame=void>
	<tr>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/1.jpg&mask=circle&w=60&h=60"alt="威零安全"/>
        <br>
        <a href="https://mp.weixin.qq.com/mp/profile_ext?action=home&__biz=Mzg4Mzg4OTIyMA====&scene=124#wechat_redirect"><sub>威零安全</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/2.jpg&mask=circle&w=60&h=60"alt="蓝剑安全"/>
        <br>
        <a href="https://mp.weixin.qq.com/mp/profile_ext?action=home&__biz=MzkxMzI5NzI5Mg==&scene=124#wechat_redirect"><sub>蓝剑实验室</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/3.jpg&mask=circle&w=60&h=60"alt="HackTwo"/>
        <br>
        <a href="https://mp.weixin.qq.com/mp/profile_ext?action=home&__biz=Mzg3ODE2MjkxMQ==&scene=124#wechat_redirect"><sub>HackTwo</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/4.jpg&mask=circle&w=60&h=60"alt="ZAC安全"/>
        <br>
        <a href="https://mp.weixin.qq.com/mp/profile_ext?action=home&__biz=MzkzMjIxMDU5OA==&scene=124#wechat_redirect"><sub>ZAC安全</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/5.jpg&mask=circle&w=60&h=60"alt="奉天安全"/>
        <br>
        <a href="https://mp.weixin.qq.com/mp/profile_ext?action=home&__biz=Mzk0NjQ2NzQ0Ng==&scene=124#wechat_redirect"><sub>奉天安全</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/6.jpg&mask=circle&w=60&h=60"alt="神农Sec"/>
        <br>
        <a href="https://xz.aliyun.com/users/141291/"><sub>神农Sec</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/7.jpg&mask=circle&w=60&h=60"alt="棉花糖"/>
        <br>
        <a href="javascript:void(0)"><sub>棉花糖</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/8.jpg&mask=circle&w=60&h=60"alt="风铃Sec"/>
        <br>
        <a href="https://mp.weixin.qq.com/mp/profile_ext?action=home&__biz=Mzk0MjY1ODE5Mg==&scene=124#wechat_redirect"><sub>风铃Sec</sub></a>
    </td>
    <td align="center">
        <img src="https://images.weserv.nl/?url=raw.githubusercontent.com/JiuZero/z0scan/main/doc/contributors/9.jpg&mask=circle&w=60&h=60"alt="X网络"/>
        <br>
        <a href="https://xheishou.com"><sub>X网络</sub></a>
    </td>
  </tr>
</table></div>

## Advantages  

1. Integration of WAF detection, fingerprint information, and plugin scanning  
2. Supports parsing parameters in complex formats like Json, XML, and pseudo-static parameters  
3. Provides data storage support (e.g., scan records) via SQLite3  
4. Open-source Python3-based tool with full cross-platform compatibility  
5. Interactive dynamic adjustment of passive scanning parameters  
6. AI-powered post-validation for JS-sensitive information  
7. Supports IPv6 domain resolution  

## Installation  

### Recommended  

Get the release version (**compiled with Nuitka for significantly improved speed & performance**): [Download](https://github.com/JiuZero/z0scan/releases)  

- Want to build an executable tailored to your environment? See: [Documentation](https://jiuzero.github.io/tags/z0scan/)  

### Not Recommended  

> PyPI updates have been discontinued since 2025.7.19  

Install via **GitHub/Gitee** clone:  
```bash  
git clone https://github.com/JiuZero/z0scan  
# https://gitee.com/JiuZero/z0scan  
cd z0scan  
pip install -r requirements.txt  
python3 z0.py help  
```  

- For **special environment installations** (e.g., Termux), see: [Documentation](https://jiuzero.github.io/tags/z0scan/)  

## Usage Examples  

### Passive Scanning  

Default configuration for **passive scanning** (forward browser traffic to port 5920):  
```  
z0 scan -s 127.0.0.1:5920  
```  

![example](doc/example0.png)  

Commonly recommended:  
```  
z0 scan -s 127.0.0.1:5920 --risk 0,1,2,3 --level 2 --disable cmdi,unauth  
```  

### Active Scanning  

Default configuration for **active scanning**:  
```  
# Active detection initiated via Burp/Yakit request traffic (recommended)  
z0 scan -s 127.0.0.1:5920  
```  

![example](doc/example1.png)  

```  
# Direct detection  
z0 scan -u https://example.com/?id=1  
# Batch detection from a URL list  
z0 scan -f urls.txt  
```  

![example](doc/example2.png)  

- For more detailed information, see: [Documentation](https://jiuzero.github.io/tags/z0scan/)  

## Plugin List  

- PerFile  

| Plugin Name          | Description                          | Risk |  
|:--------------------:|:------------------------------------:|:----:|  
| sqli-bool            | SQL Boolean-based Blind Injection    | 2    |  
| sqli-time            | SQL Time-based Blind Injection       | 2    |  
| sqli-error           | SQL Error-based Injection            | 2    |  
| codei-asp            | ASP Code Execution                   | 3    |  
| codei-php            | PHP Code Execution                   | 3    |  
| cmdi                 | Command Execution                    | 3    |  
| other-objectdese     | Deserialization Parameter Analysis   | 3    |  
| sensi-js             | JS Sensitive Information Leak        | 0    |  
| sensi-jsonp          | Jsonp Sensitive Information Leak     | 1    |  
| sensi-php-realpath   | PHP Real Path Discovery              | 0    |  
| redirect             | Redirect Vulnerability               | 1    |  
| sensi-webpack        | Webpack Source Code Leak             | 1    |  
| other-webdav-passive | WebDAV Service Passive Detection     | 1    |  
| xpathi-error         | Error-based XPATH Injection          | 2    |  
| trave-path           | Path Traversal                       | 2    |  
| sensi-backup_1       | Backup File Detection (File-based)   | 1    |  
| sensi-viewstate      | Unencrypted VIEWSTATE Discovery      | 0    |  
| xss                  | JS Semantic-based XSS Scanning       | 1    |  
| crlf_1               | CRLF Vulnerability Detection         | 2    |  
| cors-passive         | CORS Vulnerability (Passive Analysis)| 2    |  
| unauth               | Unauthorized Access Vulnerability    | 2    |  
| leakpwd-page-passive | Weak Password on Login Page          | 2    |  
| sensi-editfile       | Editor Backup File Leak              | 1    |  
| sensi-sourcecode     | Source Code Leak                     | 1    |  
| captcha-bypass       | CAPTCHA Bypass                       | 0    |  
| sensi-retirejs       | Outdated JS Component Detection      | -1   |  
| ssti                 | SSTI Vulnerability Detection         | 3    |  

- PerFolder  

| Plugin Name          | Description                          | Risk |  
|:--------------------:|:------------------------------------:|:----:|  
| sensi-backup_2       | Backup File Scan (Directory-based)   | 1    |  
| trave-list_2         | Directory Listing                    | 2    |  
| sensi-file           | Sensitive File Leak (e.g., phpinfo, .git) | /    |  
| upload-oss           | OSS Bucket Arbitrary File Upload     | 2    |  
| sensi-frontpage      | FrontPage Configuration Leak         | 1    |  

- PerServer  

| Plugin Name          | Description                          | Risk |  
|:--------------------:|:------------------------------------:|:----:|  
| sensi-errorpage      | Error Page Sensitive Information Leak| 0    |  
| xss-net              | .NET Universal XSS                   | 1    |  
| other-dns-zonetransfer | DNS Zone Transfer Vulnerability      | 1    |  
| xss-flash            | Flash Universal XSS                  | 1    |  
| other-idea-parse     | Idea Directory Parsing               | 1    |  
| other-xst            | XST Vulnerability Detection          | -1   |  
| other-webdav-active  | WebDAV Service Discovery             | 1    |  
| upload-put           | PUT-based Arbitrary File Upload      | 3    |  
| sensi-backup_3       | Backup File Detection (Domain-based) | 1    |  
| cors-active          | CORS Vulnerability (Active Detection)| 2    |  
| crlf_3               | CRLF Line Injection Vulnerability    | 2    |  
| other-hosti          | Host Header Injection Detection      | 1    |  
| other-oss-takeover   | OSS Bucket Takeover Vulnerability    | 3    |  
| sensi-iis-shortname  | IIS Short Filename Vulnerability     | 0    |  
| other-clickjacking   | Clickjacking Vulnerability           | -1   |  
| other-baseline       | Service Version Leak                 | -1   |  
| other-smuggling      | Request Smuggling Vulnerability      | 3    |  
| trave-list_3         | Directory Listing                    | 2    |  

## Changelog & License  

- Changelog: [CHANGELOG](https://github.com/JiuZero/z0scan/blob/master/doc/CHANGELOG.MD)  

- GPL-2.0 License: [LICENSE](https://github.com/JiuZero/z0scan/blob/master/LICENSE)  

## Contact the Developer  

| Platform | Contact        |  
|:--------:|:--------------:|  
| WeChat   | JiuZer1        |  
| QQ       | 1703417187     |  
| Email    | jiuzer0@qq.com |