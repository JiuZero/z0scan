* Z0SCAN CHANGE LOGS

- 2025.2.7
1. 新增PerServer插件
* IisShortName IIS短文件名漏洞 (参考lijiejie/IIS\_shortname\_Scanner)
2. 修复IIS服务正则匹配问题
3. 对指纹进行合并调整 (也做了少量的删减)
4. 向config中引入更多的配置，允许更高的自定义

- 2025.2.8
1. 修复响应头部匹配问题
2. 添加WAF被动检测逻辑 (部分正则匹配来自Wafw00f)
3. 完善服务指纹匹配以获取服务版本信息 (允许漏洞检测插件读取)
4. 对level数值范围进行调整
5. 插件调整
* 调整IisShortName插件以支持高版本IIS短文件名漏洞发现 (参考abc123info/iis7.5-10.x-ShortNameFuzz)

- 2025.2.9
1. 新增PerServer插件:
* NginxWebcache Nginx错误配置-Webcache缓存清除 (参考stark0de/nginxpwner)
* NginxCRLF Nginx错误配置-CRLF注入 (参考stark0de/nginxpwner)
* NginxVariableLeakage Nginx错误配置-变量读取 (参考stark0de/nginxpwner)

- 2025.2.10
1. 修复了baseproxy下请求编码问题
2. 添加了启发式WAF逻辑 (逻辑来自Nmap)
3. 添加服务版本匹配逻辑，允许插件调用

- 2025.2.11
1. 增加了WAF记录
2. 修复了几处Bug
3. 新增PerServer插件
* OSSBucketTakeover 可能的储存桶接管漏洞
4. 新增Fingprints指纹
* OSS.py 用于检测OSS服务
5. 对Level的划分做出调整（见插件列表）

- 2025.2.12
1. 添加了对伪静态SQL注入点的判断（目前仅支持盲注的伪静态发现）
2. 添加了对HQL语法报错的正则匹配
[] 发现SQLTime存在结果不返回问题（未知Bug）

- 2025.3.3
1. 修复了高版本Python下的模块导入问题（自此兼容性为Python >= 3.7）
2. 全面对框架进行了修订，对相应的代码做出调整，全面提供伪静态注入的支持

- 2025.3.7
1. 全面改用数据库存储及读取Waf检测历史及URL检测历史

- 2025.3.9
1. 对框架的部分功能做出细微调整
2. 插件调整
* 修复OSSBucketTakeover存在的致命Bug

- 2025.3.11
1. 新增PerFile插件
* XpathInjection Xpath注入检测
* Redirect 重定向检测

- 2025.3.13
1. 插件调整
* 优化了SQLBool的逻辑，对Payloads做出调整以实现在WAF下的检测
2. 插件描述及相关信息英文化输出
3. 部分插件实现参数分发的多线程

- 2025.3.14
1. 对终端配色方案做出调整以兼容Win下的色彩输出

- 2025.3.21
1. 调整输出方式以解决输出乱序问题
2. 提供了pip安装

- 2025.3.21 发布（实际发布时间2025.3.23）