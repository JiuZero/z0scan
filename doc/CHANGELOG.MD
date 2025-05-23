# Z0SCAN CHANGE LOGS

**2025.2.7**
1. 新增PerServer插件
* sensi-iis-shortname IIS短文件名漏洞 (参考lijiejie/IIS\_shortname\_Scanner)
1. 修复IIS服务正则匹配问题
2. 对指纹进行合并调整 (也做少量的删减)
3. 向config中引入更多的配置，允许更高的自定义

**2025.2.8**
1. 修复响应头部匹配问题
2. 添加WAF被动检测逻辑 (部分正则匹配来自Wafw00f)
3. 完善服务指纹匹配以获取服务版本信息 (允许漏洞检测插件读取)
4. 对level进行调整
5. 插件调整
* 调整sensi-iis-shortname插件以支持高版本IIS短文件名漏洞发现 (参考abc123info/iis7.5-10.x-ShortNameFuzz)

**2025.2.9**
1. 新增PerServer插件:
* other-nginx-clearcache Nginx错误配置-缓存清除 (参考stark0de/nginxpwner)
* crlf-nginx Nginx错误配置-CRLF注入 (参考stark0de/nginxpwner)
* sensi-nginx-readvar Nginx错误配置-变量读取 (参考stark0de/nginxpwner)

**2025.2.10**
1. 修复baseproxy下请求编码问题
2. 添加启发式WAF逻辑 (逻辑来自Nmap)
3. 添加服务版本匹配逻辑，允许插件调用

**2025.2.11**
1. 增加WAF记录
2. 修复几处Bug
3. 新增PerServer插件
* other-oss-takeover 可能的储存桶接管漏洞
4. 新增Fingprints指纹
* OSS 用于检测OSS服务
5. 对Level的划分做出调整（见插件列表）

**2025.2.12**
1. 对伪静态SQL注入点的判断（目前仅支持盲注的伪静态发现）
2. 对HQL语法报错的正则匹配

**2025.3.3**
1. 修复高版本Python下的模块导入问题（自此兼容性为Python >= 3.7）
2. 全面对框架进行修订，对相应的代码做出调整，全面提供伪静态注入的支持

**2025.3.7**
1. 改用数据库存储及读取Waf检测历史及URL检测历史

**2025.3.9**
1. 对框架的部分功能做出细微调整
2. 插件调整
* 修复other-oss-takeover存在的致命Bug

**2025.3.11**
1. 新增插件
* xpathi-error Xpath注入检测-基于报错
* redirect 重定向检测

**2025.3.13**
1. 插件调整
* 优化sqli-bool的逻辑，对Payloads做出调整以实现在WAF下的检测
2. 插件描述及相关信息英文化输出
3. 部分插件实现参数分发的多线程

**2025.3.14**
1. 对终端配色方案做出调整以兼容Win下的色彩输出

**2025.3.21**
1. 调整输出方式以解决输出乱序问题
2. 提供pip安装

### 2025.3.21 发布

**2025.3.25**
1. 优化框架结构: 正则规则与敏感目录字典外置于data中
2. 支持在触发WAF后的正则匹配（优先级: 正则匹配>页面差异比较）

**2025.3.26**
1. 对数据库储存结构做出调整
2. 部分插件重命名

**2025.3.27**
1. 修正相似跳过处理逻辑问题
2. logger的调用位置变动

**2025.4.6**
1. 修复HTTPS代理问题（向上兼容Python13.2+）
2. 修复多线程的变量共享问题
3. Level使用数列划分
4. 优化代码结构，减少代码量

**2025.4.12**
1. 修复线程池关闭问题
2. 插件调整
* 调整sqli-bool的Payload，降低WAF拦截率
* 加入新的sensi-js规则
1. 修复大量的SyntaxWarning
2. 对相似URL逻辑作出调整

**2025.4.13**
1. 修复一处逻辑问题&一些小Bug

### 2025.4.13 发布

**2025.4.28**
1. 对一些变量及函数名称做出调整
2. 规范化插件名称

**2025.5.1**
1. 收集并整理更多的JS敏感信息规则
2. 修复HTML报告的“详情”显示问题
3. 修复checkwaf的一处问题导致的错误返回
4. Level被重新设定为int，规范Level的划定
5. 监听ESC键以显示扫描状态

**2025.5.4**
1. 新增插件
* upload-oss OSS储存桶文件覆盖上传漏洞
* sensi-viewstate 未加密的VIEWSTATE发现（可能产生反序列化）

### 2025.5.4 发布

**2025.5.6**
1. 移除名称的变量规范化处理
2. 优化load.py的处理逻辑
3. 监听Enter键以停止/恢复将监听流量发送到扫描任务
4. 优化指纹识别逻辑，减少在指纹上的性能开销

**2025.5.7**
1. 新增插件
* upload-put PUT方法任意文件上传漏洞
* sensi-webpack webpack源码泄露漏洞
2. 删减了部分WAF匹配规则并将相似规则合并处理

**2025.5.8**
1. 新增插件
* leakpwd-page 登陆页账号密码爆破
2. 调整插件
* trave-list 增添vulscan中的检测方式

### 2025.5.12 申请404星链失败

"""
反思不足
1. 代码稳定性低，大部分插件未经过调试
2. 较xray等前辈产品，代码执行性能低
3. 支持的漏扫插件量略逊于前辈产品
"""

**2025.5.13**
1. 新增插件
* other-webdavPS Webdav检测
* other-dns-zonetransfer DNS域传输漏洞
2. 调整插件
* sqli-time 参考myscan、sqlmap修改了Payloads的生成方式

**2025.5.15**
1. 修改插件的报告生成函数框架
2. 新增插件
* other-webdavPF Webdav检测
* other-xst XST漏洞检测

**2025.5.18**
1. 修复了许多代码问题
2. 对部分插件检测逻辑进行优化