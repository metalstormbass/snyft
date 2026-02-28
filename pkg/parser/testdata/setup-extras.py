from setuptools import setup

setup(
    name='mypackage',
    version='2.0.0',
    install_requires=[
        'requests>=2.28.0',
    ],
    extras_require={
        'dev': ['pytest>=7.0', 'coverage'],
        'docs': ['sphinx>=4.0'],
    },
    dependency_links=[
        'https://github.com/user/custom-pkg/tarball/master#egg=custom-pkg-1.0',
    ],
)
