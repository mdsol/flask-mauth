# -*- coding: utf-8 -*-
#!/usr/bin/env python

import re
import sys
from os import path
from setuptools import setup, find_packages

PY26 = sys.version_info[:2] == (2, 6,)

requirements = [
    'Flask>=0.8',
    'six>=1.3.0',
    'pytz',
    'rsa',
    'cachetools',
    'requests-mauth',
    'pycrypto'
]


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
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'License :: OSI Approved :: MIT License',
    ],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    test_suite = 'tests',
    install_requires=requirements,
    tests_require=['mock>=0.8'],
    # Install these with "pip install -e '.[paging]'" or '.[docs]'
    extras_require={
        'paging': 'pycrypto>=2.6',
        'docs': 'sphinx',
    }
)