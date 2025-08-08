#!/usr/bin/env python3
"""
Bug Hunter Tool Setup Script
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="bug-hunter",
    version="1.0.0",
    author="Bug Hunter Team",
    author_email="contact@bughunter.com",
    description="Automated Bug Hunting Tool for Bug Bounty Programs",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/bughunter/bug-hunter-tool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "bug-hunter=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yaml", "templates/*.html", "wordlists/*.txt"],
    },
    zip_safe=False,
)

