# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
import datetime
import json
import xml.etree.ElementTree as ET

from typing import Dict, Mapping

from chb.tests.ELFTestCreator import ELFTestCreator

import chb.util.fileutil as UF
import chb.util.xmlutil as UX


class ELFARMTestCreator(ELFTestCreator):
    """Creates the three files that make up an arm elf test case.

    test_xxx_elf_header.xml
    test_xxx_section_16.xml  (.text section)
    test_xxx_xinfo.json
    """

    def __init__(self, test: str, bytestr: str, suite: str = "001") -> None:
        ELFTestCreator.__init__(self, test, bytestr, suite)

    @property
    def architecture(self) -> str:
        return "arm"

    @property
    def path(self) -> str:
        return "CodeHawk-Binary/tests/arm32/elf/"
