SRC_DIR = .
MAKE = make

.PHONY: install build pypi test flake8 clean

clean:
    find . -name '*.pyc' -exec rm -f {} +
	@+python -c "import shutil; shutil.rmtree('build', True)"
	@+python -c "import shutil; shutil.rmtree('dist', True)"
	@+python -c "import shutil; shutil.rmtree('z0scan.egg-info', True)"


build:
	@make clean
	python3 setup.py sdist --formats=zip bdist_wheel

pypi:
    @make build
	twine upload dist/*