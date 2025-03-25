#!/usr/bin/env python3
"""
Setup script for Hidden Rogue AP Detector
"""

from setuptools import setup, find_packages

setup(
    name="rogue_ap_detector",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool for detecting rogue wireless access points using RSSI analysis",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/hidden-rogue-ap-detector",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "scapy>=2.4.0",
        "gpsd-py3>=0.3.0",
    ],
    entry_points={
        "console_scripts": [
            "rogue-ap-detector=rogue_ap_detector:main",
        ],
    },
)
