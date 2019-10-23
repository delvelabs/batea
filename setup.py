#!/usr/bin/env python

from setuptools import setup

with open("README.md", "r") as readme_file:
    readme = readme_file.read()

version_file = "batea/__version__.py"
version_data = {}
with open(version_file) as f:
    code = compile(f.read(), version_file, 'exec')
    exec(code, globals(), version_data)


requirements = ["defusedxml==0.6.0"]

setup(
    name="batea",
    version="0.0.1",
    author="Delve Labs inc.",
    author_email="info@delvelabs.ca",
    description="Anomaly-based network scan asset ranking",
    long_description=readme,
    url="https://github.com/delvelabs/batea",
    packages=[
        'batea'
    ],
    entry_points={
        'console_scripts': [
            'batea = batea.__main__:main'
        ]
    },
    install_requires=requirements,
    license="GPLv2",
)
