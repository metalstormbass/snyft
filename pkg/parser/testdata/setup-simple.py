from setuptools import setup

setup(
    name='mypackage',
    version='1.0.0',
    install_requires=[
        'requests>=2.28.0',
        'Flask==2.3.0',
        'numpy~=1.24.0',
    ],
    setup_requires=[
        'setuptools>=40.0',
        'wheel',
    ],
)
