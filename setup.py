# -*- coding: utf-8 -*-
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

REQUIRES = ['six']

setup(
    name='stoplight',
    version='1.2.0',
    description='Input validation framework for Python',
    author='Jamie Painter',
    author_email='jamie.painter@rackspace.com',
    install_requires=REQUIRES,
    test_suite='stoplight',
    zip_safe=False,
    include_package_data=True,
    packages=find_packages(exclude=['ez_setup'])
)
