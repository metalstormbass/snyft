from setuptools import setup

with open('requirements-small.txt') as f:
    requirements = f.readlines()

setup(
    name='mypackage',
    version='1.0.0',
    install_requires=requirements,
)
