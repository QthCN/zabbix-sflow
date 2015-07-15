# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="zsflow",
    version="0.10",
    description="sFlow Zabbix Tool",
    author="Qin TianHuan",
    author_email="tianhuan@bingotree.cn",
    url="bingotree.cn",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'zsflow = zsflow.main:main',
        ],
    }
)
