# Based off of sample from https://github.com/pypa/sampleproject

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='SPF2IP',
    version='1.0.2',

    description='Python module to get IP addresses from an SPF record',
    long_description=long_description,

    url='https://github.com/nathandines/SPF2IP',

    author='Nathan Dines',
    author_email='contact@ndines.com',

    license='MIT',

    classifiers=[
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='email spf ip development firewall',

    py_modules=['SPF2IP'],

    install_requires=['dnspython>=1.13.0','ipaddress'],

    entry_points={
        'console_scripts': [
            'SPF2IP=SPF2IP:main'
        ]
    },
)
