.PHONY: all build test

pyfiles := $(shell git ls-files '*.py')

all: install_dependencies build

lint: flake8 pylint

flake8:
	flake8 $(pyfiles)

pylint:
	pylint $(pyfiles)

set_version:
	./set_version.sh

install_dependencies:
	python -m pip install --upgrade pip
	pip install -r requirements.txt

build:
	pip install --no-cache-dir .
