"""setup.py file."""

import uuid

from setuptools import setup, find_packages
from pip._internal.req import parse_requirements

__author__ = 'Yannis Ansermoz'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.requirement) for ir in install_reqs]

setup(
    name="napalm-exos",
    version="0.1.3",
    packages=find_packages(),
    author="Yannis Ansermoz",
    author_email="info@edificom.ch",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 3.9',
         'Programming Language :: Python :: 3.10',
         'Programming Language :: Python :: 3.11',
        'Operating System :: POSIX :: Linux',
    ],
    url="https://github.com/EdificomSA/napalm-exos",
    include_package_data=True,
    install_requires=reqs,
    zip_safe=False,
)
