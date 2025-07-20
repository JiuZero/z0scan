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
        if not all(key in conf.smartscan_selector for key in ["apikey", "apiurl", "model"]):
            raise ValueError("Missing required configuration in conf.smartscan_selector.")

        client = OpenAI(
            api_key=conf.smartscan_selector["apikey"],
            base_url=conf.smartscan_selector["apiurl"],
        )
        completion = client.chat.completions.create(
            model=conf.smartscan_selector["model"],
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