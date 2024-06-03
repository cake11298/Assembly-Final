# setup.py
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize("packet_sniffer.pyx")
)