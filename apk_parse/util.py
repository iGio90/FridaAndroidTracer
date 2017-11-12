# This file is part of Androguard.
#
# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import re


def read(filename, binary=True):
    with open(filename, 'rb' if binary else 'r') as f:
        return f.read()


def get_md5(buf):
    m = hashlib.md5()
    m.update(buf)
    return m.hexdigest().lower()


def get_md5_file(file_name, chunk_size=32768):
    m = hashlib.md5()
    with open(file_name, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            m.update(data)
    return m.hexdigest().lower()


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    import unicodedata
    value = unicodedata.normalize('NFKD', unicode(value)).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\s\-.]', '', value).strip())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value


def copy_zip_file(zip, name, dest_file_path, chunk_size=32768):
    """
    Copies file from the zip archive (extracts) to the normal file.
    :param zip:
    :param name:
    :param dest_file_path:
    :param chunk_size:
    :return:
    """
    with zip.open(name, 'r') as zf:
        with open(dest_file_path, 'wb') as fh:
            while True:
                data = zf.read(chunk_size)
                if not data:
                    break
                fh.write(data)
            fh.flush()
    pass


