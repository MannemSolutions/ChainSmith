#! /usr/bin/env python

"""
Create a certificate chain with a root, intermediates, and
client / server certificates.

This module installs chainsmith as a binary.
"""

import codecs
import os
import re
from setuptools import find_packages
from setuptools import setup

with open('requirements.txt', encoding="utf8") as reqfile:
    INSTALL_REQUIREMENTS = reqfile.read().split('\n')


def find_version():
    """Read the rpmbuilder version from chainsmith/__init__.py."""
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, 'chainsmith', '__init__.py'), 'r') \
            as file_pointer:
        version_file = file_pointer.read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name='chainsmith',
    version=find_version(),
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=INSTALL_REQUIREMENTS,
    entry_points={
        'console_scripts': [
            'chainsmith=chainsmith.commandline:from_yaml',
        ]
    }
)
