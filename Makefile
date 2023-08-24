.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./apachetomcatscanner.egg-info/

install: build
	pip install . --break-system-packages

build:
	python3 -m pip uninstall apachetomcatscanner --yes --break-system-packages
	pip install .[build] --break-system-packages
	python3 -m build --wheel

upload: build
	pip install .[twine]
	twine upload dist/*
