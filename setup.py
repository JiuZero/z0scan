#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/20

import setuptools
import os, io
from lib.core.settings import VERSION, SITE
import shutil
import tempfile


current_dir = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(current_dir, "README.md"), encoding="utf-8") as fd:
    desc = fd.read()
with io.open(os.path.join(current_dir, "requirements.txt"), encoding="utf-8") as fd:
    install_requires = fd.readlines()
    install_requires = [i.strip() for i in install_requires]

env_dir = tempfile.mkdtemp(prefix="z0scan-install-")
shutil.copytree(os.path.abspath(os.getcwd()), os.path.join(env_dir, "z0scan"))
os.chdir(env_dir)

setuptools.setup(
    name='z0scan',
    version=VERSION,
    author='JiuZero',
    author_email='jiuzer0@qq.com',
    description='An auxiliary active and passive scanning tool with Web and Full-Version Service vulnerability detection as the core. | 一款以Web与全版本服务漏洞检测为核心的辅助性主、被动扫描工具.',
    long_description=desc,
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["z0=z0scan.z0:main"]},
    include_package_data=True,
    package_data={"z0scan": ["*", "lib/data/*", "certs/*", "output/README", "data/*", "doc/*"]},
    long_description_content_type='text/markdown',
    keywords='z0scan, security, scanner, web, python3, pentesting,
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

dist_dir = os.path.join(env_dir, "dist")
shutil.move(dist_dir, os.path.join(current_dir, "dist"))