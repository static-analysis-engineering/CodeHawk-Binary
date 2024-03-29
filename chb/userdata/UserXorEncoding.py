# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------

import xml.etree.ElementTree as ET

import chb.util.fileutil as UF


class UserXorEncoding:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def key(self) -> str:
        xkey = self.xnode.get("key")
        if xkey is not None:
            return xkey
        else:
            raise UF.CHBError("Key missing from xor encoding")

    @property
    def width(self) -> str:
        xwidth = self.xnode.get("width")
        if xwidth is not None:
            return xwidth
        else:
            raise UF.CHBError("Width missing from xor encoding")

    @property
    def base(self) -> str:
        xbase = self.xnode.get("va")
        if xbase is not None:
            return xbase
        else:
            raise UF.CHBError("Base address missing from xor encoding")

    @property
    def size(self) -> str:
        xsize = self.xnode.get("size")
        if xsize is not None:
            return xsize
        else:
            raise UF.CHBError("Size missing from xor encoding")

    def __str__(self) -> str:
        return ('base: ' + self.base.ljust(10) + '; ' +
                'size: ' + str(self.size).ljust(6) + '; ' +
                'width: ' + str(self.width) + '; ' +
                'key: ' + self.key)
