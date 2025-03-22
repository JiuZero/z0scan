### Scanner 编写

- conf :
| 属性 | 返回类型 | 描述 |
| --------- | -------- | --------- | 
| level | int | 扫描等级 | 

- self.fingerprints :
```
dict : k, # 名称
      v # 版本信息
```
| 属性 | 返回类型 | 描述 |
| --------- | ------- | -------- | 
| os | dict | OS系统指纹 |
| webserver | dict | 中间件指纹 |
| programing | dict | 语言 |
| waf | bool | WAF状态 |

- self.requests :
| 属性 | 返回类型 | 描述 | 示例 |
| --------- | -------- | --------- | -------|
| url | str  | URL | https://www.example.com:443/a/file.php?id=1 |
| raw  | str  | 完整的请求包 | / |
| method | str |  请求方法  | GET |
| suffix  | str | 文件后缀 | .php |
| headers   | dict  |  请求头字典  | / |
| hostname  | str |  域名  | www.example.com |
| port | int |  端口 | 443 |
| cookies | dict | COOKIE | / |
| params | dict |  在URL中包含的参数  | {'id': '1'} |
| post_hint | str  | post文件上传类型  | / |
| post_data | dict |  POST数据  | / |
| data | str | 原始请求头 | / |
| netloc | str | 包含协议的域名 | https://www.example.com:443 |

- self.response :
| 属性  | 返回类型 | 描述  |
| --------- | -------- | -------- | -------|
| status_code | int | 返回状态码 | 200 |
| content | byte | 返回字节类型 | /  |
| headers    | dict | 请求头  | / |
| raw    | str | 返回包的http返回文本 | / |
| text   | str  |   返回文本  | / |

### 关于PLACE

PLACE指的是具体的漏洞注入点（请求中的可控点）
类似于requests:

+ PARAM : URL后的参数部分
+ DATA : BODY中传递的参数
+ COOKIE : COOKIE中传递的参数


## 示范

- 下面是一个插件的示范:
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlparse
import requests

from api import generateResponse, conf, KB, compare, WEB_SERVER, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = 'IIS/Nginx Parse'
    
    # 条件
    def condition(self):
        for k, v in self.fingerprints.webserver:
            if k == WEB_SERVER.IIS or k == WEB_SERVER.NGINX and 3 in conf.level:
                return True
        return False
    
    def audit(self):
        if self.condition():
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            ContentType = r.headers.get("Content-Type", '')
            if 'html' in ContentType and "allow" in r.text:
                result = self.new_result()
                # 报告初始化
                result.init_info(Type.REQUEST, #插件类型: REQUEST为主动，ANALYZE为被动
                                self.requests.hostname,
                                self.requests.url, #漏洞URL
                                VulType.CODE_INJECTION, #漏洞类型
                                PLACE.URL, #漏洞位置: URL、PARAMS、DATA、COOKIE、HEADER
                                msg=None, #漏洞利用说明
                                param=None, #漏洞参数
                                payload=None #漏洞利用Payload
                                )
                # 验证步骤(可以添加多个过程，如二次验证)
                result.add_detail("Request",
                                  r.reqinfo, # 请求体
                                  generateResponse(r), # 响应体(由generateResponse生成)
                                  "Content-Type:{}".format(ContentType) # 步骤的关键信息或步骤描述
                                  )
                self.success(result)
```
