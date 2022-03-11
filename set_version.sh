#!/bin/bash
VERSION=$(echo $GITHUB_REF | cut -d / -f 3)
if [ -z "${VERSION}" ]; then
  VERSION=$(git tag | sort -V | grep '^v' | tail -n1)-devel
fi

sed -i "s/__version__ *=.*/__version__ = '${VERSION}'/" chainsmith/__init__.py
