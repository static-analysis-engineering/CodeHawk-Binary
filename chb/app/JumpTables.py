# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs
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

from typing import Dict, List

import chb.util.fileutil as UF


class JumpTable(object):

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._tgts: List[str] = []

    @property
    def base(self) -> str:
        return self.xnode.get("start", "?")

    @property
    def targets(self) -> List[str]:
        if len(self._tgts) == 0:
            for n in self.xnode.findall("tgt"):
                addr = n.get("a")
                if addr is not None:
                    self._tgts.append(addr)
                else:
                    raise UF.CHBError("tgt element missing in jumptable")
        return self._tgts

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append('base: ' + str(self.base))
        for t in self.targets:
            lines.append('  ' + str(t))
        return '\n'.join(lines)


class JumpTables:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._tables: Dict[str, JumpTable] = {}

    @property
    def jumptables(self) -> Dict[str, JumpTable]:
        if len(self._tables) == 0:
            for x in self.xnode.findall("jt"):
                startaddr = x.get("start")
                if startaddr is not None:
                    self._tables[startaddr] = JumpTable(x)
        return self._tables
