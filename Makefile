.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./apachetomcatscanner.egg-info/

install: build
	pip install .

build:
	python3 -m pip uninstall apachetomcatscanner --yes
	pip install .[build]
	python3 -m build

upload: build
	pip install .[twine]
	twine upload dist/*
