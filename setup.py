#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/20

import setuptools
from lib.core.settings import VERSION, SITE

with open('README.md', 'r') as f:
    long_description = f.read()
with open('requirements.txt', 'r') as f:
    install_requires = f.readlines()
    install_requires = [i.strip() for i in install_requires]

setuptools.setup(
    name='z0scan',
    version=VERSION,
    author='JiuZero',
    author_email='jiuzer0@qq.com',
    description='An auxiliary active and passive scanning tool with Web and Full-Version Service vulnerability detection as the core. | 一款以Web与全版本服务漏洞检测为核心的辅助性主、被动扫描工具.',
    long_description=long_description,
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["z0=z0scan.z0:main"]},
    include_package_data=True,
    package_data={"z0scan": ["*", "lib/data/*", "certs/*", "output/README", "data/*", "doc/*"]},
    long_description_content_type='text/markdown',
    keywords='z0scan, security, scanner, web, python3, pentesting',
    platforms=['any'],
    url=SITE,
    project_urls={
        'Source': f'{SITE}', 
        'Bug Reports': f'{SITE}/issues', 
    },
    python_requires='>=3.0',
    install_requires=install_requires,
    classifiers=(
        'Environment :: Console',
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    )
)
