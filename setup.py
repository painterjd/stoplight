# -*- coding: utf-8 -*-
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

REQUIRES = ['six']

with open('README.md') as description_input:
    LONG_DESCRIPTION = description_input.read()

setup(
    name='stoplight',
    version='1.3.0',
    description='Input validation framework for Python',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/x-md',
    license='Apache License 2.0',
    url='https://pypi.org/project/stoplight/',
    platforms=['OS Independent'],
    project_urls={
        'Documentation': 'http://stoplight.readthedocs.io/en/latest/',
        'Source': 'https://github.com/painterjd/stoplight',
        'Tracker': 'https://github.com/painterjd/stoplight/issues',
    },
    author='Jamie Painter',
    author_email='jamie.painter@rackspace.com',
    install_requires=REQUIRES,
    test_suite='stoplight',
    zip_safe=False,
    include_package_data=True,
    packages=find_packages(exclude=['ez_setup']),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security'
    ]
)
