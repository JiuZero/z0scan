* Z0SCAN CHANGE LOGS

- 2025.2.7
1. 新增PerServer插件
* IIS\_short\_name IIS短文件名漏洞 (参考lijiejie/IIS\_shortname\_Scanner)
2. 修复IIS服务正则匹配问题
3. 对指纹进行合并调整 (也做了少量的删减)
4. 向config中引入更多的配置，允许更高的自定义

- 2025.2.8
1. 修复响应头部匹配问题
2. 添加WAF被动检测逻辑 (部分正则匹配来自Wafw00f)
3. 完善服务指纹匹配以获取服务版本信息 (允许漏洞检测插件读取)
4. 对level数值范围进行调整
5. 插件调整
* 调整IIS\_short\_name插件以支持高版本IIS短文件名漏洞发现 (参考abc123info/iis7.5-10.x-ShortNameFuzz)

- 2025.2.9
1. 新增PerServer插件:
* Nginx\_Webcache Nginx错误配置-Webcache缓存清除 (参考stark0de/nginxpwner)
* Nginx_CRLF Nginx错误配置-CRLF注入 (参考stark0de/nginxpwner)
* NginxVariableLeakage Nginx错误配置-变量读取 (参考stark0de/nginxpwner)

- 2025.2.10
1. 修复了baseproxy下请求编码问题
2. 添加了启发式WAF逻辑 (逻辑来自Nmap)
3. 添加服务版本匹配逻辑，允许插件调用

- 2025.2.11
1. 增加了WAF记录
2. 修复了几处Bug
3. 新增PerServer插件
* OSSFileUpload 储存桶任意文件上传
* OSSBucketTakeover 可能的储存桶接管漏洞
4. 新增Fingprints指纹
* OSS.py 用于检测OSS服务
5. 对Level的划分做出调整（见插件列表）

- 1.0.1 发布