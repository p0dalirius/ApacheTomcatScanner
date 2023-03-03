.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./apachetomcatscanner.egg-info/

install: build
	python3 setup.py install

build:
	python3 -m pip uninstall apachetomcatscanner --yes
	python3 setup.py sdist bdist_wheel

upload: build
	twine upload dist/*
