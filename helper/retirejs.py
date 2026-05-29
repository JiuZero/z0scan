#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re, os
import json
import hashlib
from urllib.parse import urlparse
from lib.core.data import KB, path

class scan(object):

    def __init__(self):
        super().__init__()
        with open(os.path.join(path.helper, "retirejs.json")) as f:
            self.definitions = json.load(f)
    
    def is_defined(self, o):
        return o is not None
    
    def deJSON(self, data):
        data =  data.replace('\\\\', '\\')
        return data

    def scan(self, data, extractor, matcher=None):
        matcher = matcher or self._simple_match
        detected = []
        for component in self.definitions:
            extractors = self.definitions[component].get("extractors", None).get(extractor, None)
            if (not self.is_defined(extractors)):
                continue
            for i in extractors:
                match = matcher(i, data)
                if (match):
                    detected.append({"version": match,
                                     "component": component,
                                     "detection": extractor})
        return detected

    def _simple_match(self, regex, data):
        regex = self.deJSON(regex)
        match = re.search(regex, data)
        return match.group(1) if match else None


    def _replacement_match(self, regex, data):
        try:
            regex = self.deJSON(regex)
            group_parts_of_regex = r'^\/(.*[^\\])\/([^\/]+)\/$'
            ar = re.search(group_parts_of_regex, regex)
            search_for_regex = "(" + ar.group(1) + ")"
            match = re.search(search_for_regex, data)
            ver = None
            if (match):
                ver = re.sub(ar.group(1), ar.group(2), match.group(0))
                return ver
            return None
        except:
            return None

    def _scanhash(self, hash):
        for component in self.definitions:
            hashes = self.definitions[component].get("extractors", None).get("hashes", None)
            if (not self.is_defined(hashes)):
                continue
            for i in hashes:
                if (i == hash):
                    return [{"version": hashes[i],
                             "component": component,
                             "detection": 'hash'}]
        return []

    def check(self, results):
        for r in results:
            result = r
            if (not self.is_defined(self.definitions[result.get("component", None)])):
                continue
            vulns = self.definitions[result.get("component", None)].get("vulnerabilities", None)
            if vulns:
                for i in range(len(vulns)):
                    if (not self._is_at_or_above(result.get("version", None), vulns[i].get("below", None))):
                        if (self.is_defined(vulns[i].get("atOrAbove", None)) and not self._is_at_or_above(result.get("version", None), vulns[i].get("atOrAbove", None))):
                            continue
                        vulnerability = {"info": vulns[i].get("info", None)}
                        if (vulns[i].get("severity", None)):
                            vulnerability["severity"] = vulns[i].get("severity", None)
                        if (vulns[i].get("identifiers", None)):
                            vulnerability["identifiers"] = vulns[i].get("identifiers", None)
                        result["vulnerabilities"] = result.get("vulnerabilities", None) or []
                        result["vulnerabilities"].append(vulnerability)
        return results
    
    def unique(self, ar):
        return list(set(ar))

    def _is_at_or_above(self, version1, version2):
        # print "[",version1,",", version2,"]"
        v1 = re.split(r'[.-]', version1)
        v2 = re.split(r'[.-]', version2)
        l = len(v1) if len(v1) > len(v2) else len(v2)
        for i in range(l):
            v1_c = self._to_comparable(v1[i] if len(v1) > i else None)
            v2_c = self._to_comparable(v2[i] if len(v2) > i else None)
            # print v1_c, "vs", v2_c
            if (not isinstance(v1_c, type(v2_c))):
                return isinstance(v1_c, int)
            if (v1_c > v2_c):
                return True
            if (v1_c < v2_c):
                return False
        return True


    def _to_comparable(self, n):
        if (not self.is_defined(n)):
            return 0
        if (re.search(r'^[0-9]+$', n)):
            return int(str(n), 10)
        return n


    def _replace_version(self, jsRepoJsonAsText):
        return re.sub(r'[.0-9]*', '[0-9][0-9.a-z_\\-]+', jsRepoJsonAsText)


    def scan_url(self, url):
        result = self.scan(url, 'url')
        return self.check(result)


    def scan_filename(self, fileName):
        result = self.scan(fileName, 'filename')
        return self.check(result)


    def scan_file_content(self, content):
        result = self.scan(content, 'filecontent')
        if (len(result) == 0):
            result = self.scan(content, 'filecontentreplace', self._replacement_match)
        if (len(result) == 0):
            result = self._scanhash(
                hashlib.sha1(content.encode('utf8')).hexdigest())
        return self.check(result)


    def main_scanner(self, url, response):
        url_scan_result = self.scan_url(url)
        filecontent = response
        filecontent_scan_result = self.scan_file_content(filecontent)
        url_scan_result.extend(filecontent_scan_result)
        if not url_scan_result:
            url_scan_result = self.scan_filename(url)
        result = {}
        if url_scan_result:
            result['component'] = url_scan_result[0]['component']
            result['version'] = url_scan_result[0]['version']
            result['vulnerabilities'] = []
            vulnerabilities = set()
            for i in url_scan_result:
                k = set()
                try:
                    for j in i['vulnerabilities']:
                        vulnerabilities.add(str(j))
                except KeyError:
                    pass
            for vulnerability in vulnerabilities:
                result['vulnerabilities'].append(json.loads(vulnerability.replace('\'', '"')))
            return result

    def js_extractor(self, response):
        """Extract js files from the response body"""
        scripts = []
        matches = re.findall(r'<(?:script|SCRIPT).*?(?:src|SRC)=([^\s>]+)', response)
        for match in matches:
            match = match.replace('\'', '').replace('"', '').replace('`', '')
            scripts.append(match)
        return scripts

main_scanner = scan().main_scanner
js_extractor = scan().js_extractor
