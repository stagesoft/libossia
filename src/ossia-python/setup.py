#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
setup for the pyossia project
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
import sys

# To use a consistent encoding
from codecs import open
from os import path
HERE = path.abspath(path.dirname(__file__))
# Get the long description from the README file
with open(path.join(HERE, 'README.rst'), encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()

# get current version
import versioneer
__version__ = versioneer.get_version()


try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
    class bdist_wheel(_bdist_wheel):
        def finalize_options(self):
            _bdist_wheel.finalize_options(self)
            self.root_is_pure = False
except ImportError:
    sys.exit("ERROR: setup.py: you must install wheel (pip2/3 install wheel)")

setup(
    name = 'pyossia',
    version =__version__,
    description = 'libossia is a modern C++, cross-environment distributed object model for creative coding and interaction scoring Edit',
    long_description = LONG_DESCRIPTION,
    url = 'https://github.com/ossia/libossia/ossia-python',
    author = 'OSSIA team',
    author_email = 'contact@ossia.io',
    license ='GPLv3+',
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    keywords = ['creative', 'controls', 'osc', 'oscquery', 'websocket', 'libossia', 'midi'],
    packages = find_packages(),
    cmdclass={

    'bdist_wheel': bdist_wheel
    },
    package_data={
        'pyossia': ['*.so'],
    },
    include_package_data=True,
    zip_safe=False
)
