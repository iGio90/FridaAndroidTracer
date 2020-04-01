"""
    Dwarf - Copyright (C) 2020 Giovanni - iGio90 - Rocca
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""
from setuptools import setup, find_packages

setup(
    # Package info
    name='FridaAndroidTracer',
    version='1.0.0',
    author="Giovanni - iGio90 - Rocca",
    author_email="giovanni.rocca.90@gmail.com",
    license='GPLv3+',
    description=
    "Android applications framework to perform a general audit",
    long_description=
    "Android applications framework to perform a general audit",
    long_description_content_type="text/markdown",
    url="https://github.com/iGio90/FridaAndroidTracer",
    packages=find_packages(),
    python_requires='>=3',
    zip_safe=False,
    include_package_data=True,
    # Dependencies
    install_requires=[
        'm2crypto',
        'gpapi',
        'pyaxmlparser'
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Science/Research",
        "Topic :: Security"
    ]
)
