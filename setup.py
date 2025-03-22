#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
# os.chdir(env_dir)


setuptools.setup(
    name='z0scan',
    version=VERSION,
    author='JiuZero',
    author_email='jiuzer0@qq.com',
    description='Z0SCAN Web Application Scanner',
    long_description=desc,
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["z0scan=z0scan.z0scan:main"]},
    package_data={"z0scan": ["*", "data/*"]},
    include_package_data=True,
    long_description_content_type='text/markdown',
    keywords='z0scan, security, scanner, web, python3',
    platforms=['any'],
    url=SITE,
    python_requires='>=3.6',
    install_requires=install_requires,
    classifiers=(
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)"
    )
)
