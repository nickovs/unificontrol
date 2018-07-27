# Setup file for unificontrol
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="unificontrol",
    version="0.2.0",
    author="Nicko van Someren",
    author_email="nicko@nicko.org",
    description="Secure access to Ubiquiti Unifi network controllers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nickovs/unificontrol",
    packages=setuptools.find_packages(),
    classifiers=(
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ),
    install_requires=['requests'],
    python_requires='>=3.4',
    keywords=['unifi', 'wifi', 'network', 'mamangement'],
)
