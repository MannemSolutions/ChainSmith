#! /usr/bin/env python

"""
Create a certificate chain with a root, intermediates, and
client / server certificates.

This module installs chainsmith as a binary.
"""

import codecs
import os
import re
import pathlib
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


# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name='chainsmith',
    version=find_version(),
    description='A tool for easy creation of certificate chains',
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/MannemSolutions/ChainSmith",
    author="Sebastiaan Mannem",
    author_email="sebas@mannemsolutions.nl",
    license="GPL-3.0 License",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    include_package_data=True,
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=INSTALL_REQUIREMENTS,
    entry_points={
        'console_scripts': [
            'chainsmith=chainsmith.commandline:from_yaml',
        ]
    }
)
