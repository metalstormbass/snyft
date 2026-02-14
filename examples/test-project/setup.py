from setuptools import setup, find_packages

setup(
    name='test-project',
    version='1.0.0',
    description='A test project for Snyft code analysis',
    author='Test Author',
    author_email='test@example.com',
    packages=find_packages(),
    install_requires=[
        'flask>=3.0.0',
        'requests>=2.31.0',
    ],
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
