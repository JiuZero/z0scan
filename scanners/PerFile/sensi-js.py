#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4

import re
import json
from config.others.JsSensi import rules
from api import VulType, Type, PluginBase, conf, KB, logger, chat


class Z0SCAN(PluginBase):
    name = "sensi-js"
    desc = 'JS Sensitive Information Leak (with AI Context Validation)'
    version = "2025.3.4"
    risk = 0
        
    def audit(self):
        if not self.requests.suffix == ".js" or not self.risk in conf.risk or self.name in KB.disable:
            return
            
        js_content = self.response.text
        for name, pattern in rules.items():
            matches = re.finditer(pattern, js_content, re.M | re.I)
            found_valid = False
            
            for match in matches:
                text = match.group()
                # 基础过滤
                ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                if any(ignore_word in text for ignore_word in ignores):
                    continue

                start_pos = max(0, match.start() - 100)
                end_pos = min(len(js_content), match.end() + 100)
                context = js_content[start_pos:end_pos]

                marked_context = (
                    context[:match.start()-start_pos] + 
                    "【SENSITIVE_START】" + 
                    context[match.start()-start_pos:match.end()-start_pos] + 
                    "【SENSITIVE_END】" + 
                    context[match.end()-start_pos:]
                )

                if conf.smartscan_selector["enable"]:
                    valid, type, reason = self._ai_validate_with_context(marked_context, name, pattern)
                    if not valid:
                        continue

                result = self.generate_result()
                result.main({
                    "type": Type.ANALYZE,
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE, 
                    "show": {
                        "Match": f"{text}",
                        "Type": str(name) if not conf.smartscan_selector["enable"] else type
                        }
                    })
                description = f"Found valid sensitive information using pattern {pattern}: {text}"
                if conf.smartscan_selector["enable"]:
                    description += f", Analysis given by AI: {reason}"
                result.step("Request Details", {
                    "request": self.requests.raw, 
                    "response": self.response.raw, 
                    "description": description
                    })
                self.success(result)
                found_valid = True
                break
                
            if found_valid:
                break
                
    def _ai_validate_with_context(self, context, name, pattern):
        prompt = f"""
            Please analyze whether the marked sensitive information in the following JavaScript code is genuine:

            {context}


            Rule Name: {name}
            Matching mode: {pattern}

            Key points to consider:
            1. The context in which the information appears
            2. Whether it's in comments or test data
            3. Whether it matches common patterns for this type of sensitive information

            Respond strictly in the following JSON format:
            {{
                "valid": boolean,    // Whether it's valid sensitive info
                "confidence": float, // Confidence level (0.0~1.0)
                "type": string,     // Type of sensitive info (e.g., API key, password)
                "reason": string    // Detailed analysis rationale
            }}
        """
        
        try:
            response = chat(prompt)
            if not response:
                return False
                
            try:
                analysis = json.loads(response.content)
                # 置信度阈值到0.8
                if analysis.get('valid', False) and analysis.get('confidence', 0) > 0.8:
                    return True, analysis.get('type', ''), analysis.get('reason', '')
            except json.JSONDecodeError:
                logger.error(f"AI response format error, raw response: {response.content}")
                return False, None, None
                
        except Exception as e:
            logger.error(f"Error during AI validation: {e}")
            return False, None, None
            
        return False, None, None