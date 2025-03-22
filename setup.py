# -*- coding: utf-8 -*-

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
    description='Z0SCAN Web Application Scanner',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='z0scan, security, scanner, web, python3',
    platforms=['any'],
    url=SITE,
    python_requires='>=3.6',
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    include_package_data=True,
    classifiers=(
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)"
    ),
    entry_points={
        'console_scripts': [
            'z0scan = z0scan:main'
        ]
    }
)
