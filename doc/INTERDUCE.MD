## Z0SCAN

### 介绍&特性
Z0SCAN 是一款为较高风险资产漏洞检测而开发的被动扫描工具.

它相较于其它被动扫描器更为超凡脱俗:

1. WAF判断与插件扫描的联动
- 在判断出WAF后，z0scan将对插件做出相应调整（不妨去看一看SQLBool的源码呗，我想你会喜欢它的Payload），尽可能降低请求量与被WAF所拦截的概率
当然咯，WAF在经过一次扫描后会记录host到数据库中以减少重复检测（启发式检测的Payload可是很高banIP率的）

2. 不只是TOP10
- z0scan的定位是扫其它被动扫描器所不扫，如果你阅读过它的源码你会注意到混杂了HQL报错匹配的SQLError插件…

3. 一个奇特的Level划分方式: list
- 我想这将能够方便用户快速地做出调整，以适应不同的需求~（个人比较厌恶把插件一个个disable掉）
关于Level的划分:
```
Level: 0 # 被动分析插件
Level: 1 # SQLi, XSS
Level: 2 # 目录枚举
Level: 3 # 中间件漏洞
Level: 4 # 命令执行等非常见漏洞
```

4. 关于伪静态参数的支持
- 你可以在config中设置它：
```
PSEUDO_STATIC_KEYWORDS = ['id', 'pid', 'zid', 'user', 'page', 'category', 'column_id', 'tty'] # 伪静态SQL关键点参数（忽略大小写）
```
- 它能够识别类似于这样的一些伪静态参数：
```
/id/1.html # id: 1
/info/tty-12-id-1.html # tty: 12, id: 1
/info/user_admin.html # user: admin
```


5. 部分插件依托于被动指纹
- 以指纹要素作为插件工作的前提条件，这将有效减少请求量并实现更具针对性的检测
在插件中你或许可以看到这样的条件判断:
```
def condition(self):
    for k, v in self.fingerprints.webserver:
        if k == WEB_SERVER.NGINX and compare("0.0.1", "0.8.37", v):
            return True
        elif k == WEB_SERVER.IIS and compare("7.0", "7.5", v):
            return True
    return False
```
指纹要求精确到了版本（但实际上很少有网站会将版本信息返回）

6. “相似”去重机制
- 不同于w13scan，z0scan将于扫描开始前将请求的特征与数据库中的数据进行比对，跳过相似的请求
如: http://example.cn/id/3/pid/1.html 与 http://example.cn/id/68/pid/7.html
- 当然你可以在config.py中关闭它：
```
SKIP_SIMILAR_URL = True # 是否跳过相似URL下的扫描以减少请求
```

### 安装

GitHub克隆安装

```
git clone https://github.com/JiuZero/z0scan
cd z0scan
pip install -r requirements.txt
python3 z0scan.py
```

从Pypi中安装

```
pip install z0scan
```

