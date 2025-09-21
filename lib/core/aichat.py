#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/7/20

from openai import OpenAI, OpenAIError
from lib.core.data import conf
from lib.core.log import logger
import sys

def chat(text):
    try:
        # 验证配置
        if not all(key in conf.smartscan for key in ["api_key", "api_url", "model"]):
            raise ValueError("Missing required configuration in conf.smartscan.")

        client = OpenAI(
            api_key = conf.smartscan["api_key"],
            base_url = conf.smartscan["api_url"],
        )
        completion = client.chat.completions.create(
            model = conf.smartscan["model"], 
            messages=[
                {"role": "user", "content": text}
            ],
        )
        return completion.choices[0].message
    except OpenAIError as e:
        logger.error(f"OpenAI API error: {e}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return None