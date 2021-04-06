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
from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.app.BDictionary


class DictionaryRecord:
    """Base class for all objects kept in a Dictionry."""

    def __init__(
            self,
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        self.index = index
        self.tags = tags
        self.args = args

    def get_key(self) -> Tuple[str, str]:
        return (",".join(self.tags), ",".join([str(x) for x in self.args]))

    def write_xml(self, node: ET.Element) -> None:
        (tagstr, argstr) = self.get_key()
        if len(tagstr) > 0:
            node.set("t", tagstr)
        if len(argstr) > 0:
            node.set("a", argstr)
        node.set("ix", str(self.index))


class BDictionaryRecord(DictionaryRecord):
    """Base class for all objects kept in the BDictionary."""

    def __init__(self,
                 d: "chb.app.BDictionary.BDictionary",
                 index: int,
                 tags: List[str],
                 args: List[int]) -> None:
        DictionaryRecord.__init__(self, index, tags, args)
        self.d = d
