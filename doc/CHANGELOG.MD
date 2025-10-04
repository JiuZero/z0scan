# Z0SCAN CHANGE LOGS

**2025.2.7**
1. 对指纹进行合并调整 (也做少量的删减)
2. 向config中引入更多的配置，允许更高的自定义
3. 新增插件
* PerDomain/sensi-iis-shortname IIS短文件名漏洞

**2025.2.8**
1. 修复响应头部匹配问题
2. 添加WAF被动检测逻辑 (部分正则匹配来自Wafw00f)
3. 完善服务指纹匹配以获取服务版本信息 (允许漏洞检测插件读取)
4. 对level进行调整

**2025.2.10**
1. 修复baseproxy下请求编码问题
2. 添加启发式WAF逻辑 (逻辑来自Nmap)

**2025.2.11**
1. 增加WAF记录
2. 修复几处Bug
3. 校准level的定义（见插件列表）
4. 新增插件
* PerDomain/other-oss-takeover 可能的储存桶接管漏洞

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

**2025.3.11**
1. 新增插件
* PerPage/xpathi-error Xpath注入检测-基于报错
* PerPage/redirect 重定向检测

**2025.3.13**
1. 插件调整
* PerPage/sqli-bool 优化逻辑，对Payloads做出调整以实现在WAF下的检测
2. 插件描述及相关信息英文化输出
3. 部分插件实现参数分发的多线程

**2025.3.14**
1. 对终端配色方案做出调整以兼容Win下的色彩输出

**2025.3.21**
1. 调整输出方式以解决输出乱序问题
2. 提供pip安装

### 0.0.2.9 发布

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
3. 优化代码结构，减少代码量

**2025.4.12**
1. 修复线程池关闭问题
2. 插件调整
* PerPage/sqli-bool 调整Payload，降低WAF拦截率
3. 规则调整
* rule/sensi_js 加入新的规则
4. 对相似URL逻辑作出调整

**2025.4.13**
1. 修复一处逻辑问题&一些小Bug

### 0.0.4.3 发布

**2025.4.28**
1. 对一些变量及函数名称做出调整
2. 规范化插件名称

**2025.5.1**
1. 收集并整理更多的JS敏感信息规则
2. 修复HTML报告的“详情”显示问题
3. 修复checkwaf的一处问题导致的误报
4. 监听ESC键以显示扫描状态

**2025.5.4**
1. 新增插件
* PerPage/sensi-viewstate 未加密的VIEWSTATE发现（可能产生反序列化）

### 0.0.6 发布

**2025.5.6**
1. 移除名称的变量规范化处理
2. 优化load.py的处理逻辑
3. 监听Enter键以停止/恢复将监听流量发送到扫描任务
4. 优化指纹识别逻辑，减少在指纹上的性能开销

**2025.5.7**
1. 新增插件
* PerPage/sensi-webpack webpack源码泄露漏洞
2. 删减了部分WAF匹配规则并将相似规则合并处理

**2025.5.8**
1. 调整插件
* PerDir/trave-list 增添vulscan中的检测方式

### 2025.5.12 申请404星链失败

```
反思不足
1. 代码稳定性低，大部分插件未经过调试
2. 较xray等前辈产品，代码执行性能低
3. 支持的漏扫插件量远逊于前辈产品
```

**2025.5.13**
1. 新增插件
* PerPage/other-webdav Webdav检测
* PerDomain/other-dns-zonetransfer DNS域传输漏洞
2. 调整插件
* PerPage/sqli-time 参考myscan、sqlmap修改了Payloads的生成方式
3. 对框架做出调整，提高代码可读性

**2025.5.15**
1. 修改插件的报告生成函数框架
2. 新增插件
* PerDomain/other-webdav Webdav检测
* PerDomain/other-xst XST漏洞检测
3. 修复了部分WAF指纹正则导致的误判问题
4. 修复了WAF检测逻辑问题

**2025.5.18**
1. 修复了许多代码问题
2. 对部分插件检测逻辑进行优化

**2025.5.19**
1. 增添risk设置以指定要扫描的漏洞危害等级
2. 新增插件
* PerPage/cors CORS漏洞检测
* PerDomain/cors CORS漏洞检测
3. 简化WAF匹配框架并删减规则保留Top

**2025.5.20**
1. 新增插件
* PerPage/xss XSS漏洞检测
2. 提供ipv6的支持

**2025.5.22**
1. 新增插件
* PerDomain/upload-put PUT请求任意文件上传
* PerPage/crlf CRLF换行注入漏洞
* PerDomain/crlf CRLF换行注入漏洞

**2025.5.23**
1. 提供对json、xml及文件上传的请求包的参数解析&注入的支持
2. 修复因为框架修改而导致的html报告异常问题
3. 移除键盘监听以恢复对Termux等环境的支持

### 0.0.7.5 发布

**2025.6.3**
1. 优化了插件内线程的处理，减少依赖项
2. 修复输出显示问题
3. 新增插件
* PerPage/leakpwd-page-passive 登陆页账号密码爆破（被动）

**2025.6.4**
1. 优化html报告模板，提供统计图数据展示

**2025.6.6**
1. 新增插件
* PerDomain/other-hosti Host注入检测
* PerPage/sensi-sourcecode 源码泄露
* PerDomain/sensi-editfile 编辑文件泄露

### 0.0.8.0 发布

**2025.6.14**
1. 修复大量Bug（太多了，略过）
2. 修改WAF检测逻辑，不再使用启发式判断
3. 新增插件
* PerPage/captcha-bypass 验证码绕过
4. 独立插件内置线程为模块（移除了future依赖项）

### 0.0.9.9 发布

**2025.6.5**
1. 修复SyntaxWarning问题
2. 修复other-hosti中的Bug并为xpathi-error增添报错匹配规则
3. 新增插件
* PerDomain/other-clickjacking 点击劫持

### 0.1.0.1 发布

**2025.6.6**
1. 修复URL包含参数而requests中通过params二次引入参数产生的参数污染问题

**2025.6.8**
1. 再度优化框架结构(移除目录data，新增目录config、lib/reverse、lib/data)
2. 反连平台初始化操作关联至z0命令中
3. 优化config/lists(原data/dict)的初始化引入

**2025.6.10**
1. 新增插件
* PerDomain/other-smuggling HTTP走私
* PerPage/other-retirejs 过时的JS组件漏洞

**2025.6.14**
1. 调整插件
* PerPage/sensi-json 按照myscan增添了接受外部网站请求的报告输出
* PerDomain/crlf_3 按照crlfsuite的检测方式做出修改
2. 提供docker安装方案

**2025.6.19**
1. 新增插件
* PerPage/ssti SSTI模板注入
2. 新增对于requests编码问题补丁

**2025.6.22**
1. 调整插件
* PerPage/sensi-php-realpath 修复参数污染问题

**2025.6.24**
1. 支持二级主动扫描(仅PerPage检测)
2. 修复少量Bug（致命Bug）

**2025.6.26**
1. 支持设定最大目录扫描深度
2. 移除插件
* PerDir/sensi-php-phpinfo phpinfo文件探测
* PerDir/sensi-repository .git.hg等敏感文件扫描
3. 新增插件
* PerDir/sensi-file 各类敏感文件扫描

**2025.6.28**
1. 修复PerDomain/crlf_3误报问题
2. 向部分插件引入Threads并缩小检测条件（更低请求量）
3. 对Z0的指纹进行优化（参考Sitadel）
4. 新增参数list以列出插件&模糊字典

### 0.1.2.2 发布

### 2025.6.30 申请404星链失败

```
反思不足
1. 缺乏差异化优势（创新！创新！创新！）
```

**2025.7.1**
1. 调整插件
* PerPage/trve-path 参考GourdScanV2新增规则
* PerPage/xpathi-error 参考GourdScanV2新增规则

**2025.7.3**
1. 支持dbcmd参数以管理数据库信息

**2025.7.4**
1. 调整插件
* PerDomain/other-hosti 报错处理：非标准HTTP响应
2. 支持console模式以实时交互被动扫描配置（支持暂停将流量转发到插件）

**2025.7.5**
1. 优化baseproxy缓存机制，减少性能开销
2. 优化数据库结构
3. 支持动态补齐指纹信息
4. 修复console客户端的阻塞问题并增加超时处理

**2025.7.17**
1. 使用nuitka编译为可执行文件~
2. 再度优化baseproxy

**2025.7.18**
1. 对ZeroMQ载入失败进行处理，使用socket服务取代（不依赖于pyzmq）
2. 修复多处无效的转义序列问题
3. 修复编译后终端输出问题
4. 数据库参数化查询与插入

### 0.1.3.5 发布

**2025.7.19**
1. 修订requests补丁，实现0编码请求
2. 调整插件
* PerPage/crlf_1 解决换号字符串被错误识别为换行而导致的误报问题
3. console支持set disable
4. logo.png

**2025.7.20**
1. AI智能插件优化加入（暂时只用于干涉sensi-js）
2. 新增paramanalyzer用于避免不必要的漏洞检测请求，减少请求量

**2025.7.23**
1. 修复由Lay0us反馈的一处命名问题
2. 优化部分代码

### 0.1.4.1 发布

**2025.7.27**
1. 优化baseproxy处理，缓解流量竞争
2. 修复登陆页弱口令检测解析部分代码的一处问题
3. 优化插件编码处理

### 0.1.4.4 发布

**2025.7.28**
1. "None" != None !!!
2. 修复JSON的处理问题
3. 调整优化requests补丁中对params&data的处理
4. 对部分代码做出细微的调整
5. 新增漏洞隐患提醒功能
6. 移除二级主动扫描（可以通过雪瞳/FindSomething + Z0实现更好的效果）
7. 增加SqlError规则

### 0.1.5.1 发布

**2025.7.29**
1. 修复Sql报错正则错误而导致的误报问题
2. 调整插件：加入DetSQL的概率计算算法
* PerPage/sqli-bool
* PerPage/sqli-error
* PerPage/sqli-time
3. 感谢**steveopen1**
* 提供反连平台DNS端口配置的建议&相应完善代码
4. 修正插件英译介绍
5. 新增插件
* PerPage/ssti-angularjs 参考tijme/angularjs-csti-scanner实现的AngularJS客户端模板注入

### 0.1.5.6 发布

**2025.8.7**
1. 感谢**hughink**
* 反馈other-hosti的报告生成问题

### 0.1.5.7 发布

**2025.8.14**
1. 优化初始化逻辑（为动态开关插件铺垫）
2. IP封禁判断&目标黑名单处理
3. redis数据库引入！（为分布式铺垫）
4. 新增对请求失败数量&请求数量的统计
5. 移除对ZeroMQ的支持

**2025.8.15**
1. 支持动态开关插件
2. 锁定loader为单线程以更好地发挥去重效果
3. 新增更多的命令行参数

**2025.8.16**
1. 新增扫描状态显示
2. 优化部分代码逻辑

**2025.8.17**
1. 整理并优化初始化流程
2. 支持LDAP反连
3. 支持开关DNS,LDAP等反连

**2025.8.20**
1. 新增插件
* PerPage/other-fastjson-blind Fastjson反序列化Dnslog无回显
* PerPage/other-json-error Json序列化组件报错检测(可能的反序列化)
* PerPage/cmdi-blind 从cmdi中分离出的无回显检测
* PerPage/sqli-dnslog 基于Dnslog的无回显SQL注入检测
* PerPage/xxe XXE外部实体注入
* PerPage/xxe-blind 无回显XXE检测
2. 调整插件
* cmdi 借鉴myscan的检测方式

**2025.8.21**
1. 新增对反连插件关闭提示
2. 支持客户端验证服务端反连服务存活状态

**2025.8.24**
1. 支持微信推送&钉钉推送
2. 支持获取免费代理/爬取空间搜索引擎代理
3. 支持导入代理文件(json,txt)

**2025.8.26**
1. 支持命令行报告记录(储存为txt)
2. 继续整理优化初始化逻辑
3. 优化WAF检测限制
4. 优化log输出方案

**2025.8.29**
1. z0的可视化实现：ling

### 0.1.8.9 发布 - 七夕快乐！

**2025.9.1**
1. 感谢**9Insomnie（n0irx）**
* Fix SSL import error and socket_port configuration issue

**2025.9.6**
1. 新增插件
* PerPage/other-redos 正则dos漏洞检测
* PerPage/other-jndi-error 基于报错的jndi注入漏洞检测
* PerPage/codei-java Java代码注入漏洞

**2025.6.7**
1. 修复json报告格式问题
2. 修复ling对json报告的解析问题
3. 美化HTML报告模板
4. ling支持定位可执行文件z0
5. build支持编译打包ling

### 0.1.9.9 发布

### 0.2.0.0 发布

**2025.6.8**
1. 感谢**dsal15326770**反馈
* baseproxy 代理变量缺失问题
* other-dns-zonetransfer 逻辑判断问题
2. 修复多处变量未定义问题

### 0.2.0.3 发布

**2025.9.12**
1. 针对服务器主机端口漏洞: PerHost
2. 新增插件
* PerHost/unauth-docker
* PerHost/unauth-redis
* PerHost/unauth-junkins
* PerHost/unauth-rsync
* PerHost/unauth-memcached
* PerHost/unauth-mongodb
* PerHost/unauth-zookeeper
* PerHost/unauth-solr
* PerHost/leakpwd-redis
* PerHost/leakpwd-mssql
* PerHost/leakpwd-mysql
* PerHost/leakpwd-postgresql
* PerHost/leakpwd-smb
* PerHost/other-solr-rce
* PerHost/other-ftp-anonymous

**2025.9.13**
1. 感谢**你好**反馈
* 修复aichat变量错误命名

### 9.18 - 勿忘国耻

**2025.9.18**
1. 参考myscan修缮requests_patch
2. 优化项目结构

**2025.9.21**
1. 移除scanner_folder命令行参数
2. 命令行参数命名load -> enable, disload -> disable
3. 修复autoproxy fetch部分代码

**2025.9.22**
1. QSS美化ling的界面

**2025.9.24**
1. 感谢**dsal15326770**反馈
* other-dns-zonetransfer 实现逻辑存在问题

### 0.2.2.3 发布

**2025.9.23**
1. 设置Pyinstaller绑定ling的qss与logo文件
2. 同步ling对于z0的绑定参数变更
3. 修复pymysql模块丢失

### 0.2.2.5 发布

**2025.9.27**
1. 移除autoproxy - 维护要求高
2. 重新设定部分self.requests与self.response中的数据名 - 增加代码可读性
3. 支持版本更新检测(不考虑实现版本更新获取功能)

### 10.1 - 祝愿祖国繁荣昌盛

**2025.10.1**
1. ling 界面改用qfluentwidgets组件
2. ling 做出大量功能性更新（包括界面、功能、性能）
3. 修复大量插件Bug
4. console改用Web界面

### 0.3.1.1 发布

1. 修复console插件启闭问题
2. 修复ling settings文件缺失导致的界面显示问题
3. 添加对linux-arm64支持

### 0.3.1.1 重发布