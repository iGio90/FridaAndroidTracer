A framework built on top of Frida that generates a JSON report of the given Android application. 

It traces api involved with sensitive information, network requests, receivers and more.

Here an [example output](https://gist.github.com/iGio90/1ccf624ff0f55608b061985c03e61cae)

##### Setup

```
git clone https://github.com/iGio90/FridaAndroidTracer
cd FridaAndroidTracer
python3 setup.py install
```

##### Run

```
usage: tracer.py [-h] -p PACKAGE [-pd] [-f FILE_PATH] [-s SCRIPT_PATH]
tracer.py: error: the following arguments are required: -p/--package
```

```
    Copyright (C) 2020 Giovanni - iGio90 - Rocca
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
```