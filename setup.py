# -*- coding: utf-8 -*-
# !/usr/bin/env python

import re
from os import path

from setuptools import find_packages, setup

version_file = path.join(
    path.dirname(__file__),
    'flask_mauth',
    '__version__.py'
)
with open(version_file, 'r') as fp:
    m = re.search(
        r"^__version__ = ['\"]([^'\"]*)['\"]",
        fp.read(),
        re.M
    )
    version = m.groups(1)[0]

setup(
    name='Flask-MAuth',
    version=version,
    license='MIT',
    url='https://www.github.com/mdsol/flask-mauth/',
    author='Geoff Low',
    author_email='glow@mdsol.com',
    description='MAuth Client and Server Library for MAuth',
    packages=find_packages(exclude=['tests']),
    classifiers=[
        'Framework :: Flask',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
    ],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    test_suite='tests',
    tests_require=['mock'],
    extras_require={
        'docs': 'sphinx',
    }
)
