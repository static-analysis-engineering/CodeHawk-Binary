# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs
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

from typing import Dict, List, Optional

import chb.util.fileutil as UF


class DataBlock:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def startaddr(self) -> str:
        return self.xnode.get("start", "?")

    @property
    def endaddr(self) -> str:
        return self.xnode.get("end", "?")

    @property
    def name(self) -> Optional[str]:
        return self.xnode.get("name", None)

    def __str__(self) -> str:
        return "DB:" + self.startaddr + "-" + self.endaddr


class DataBlocks:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._datablocks: List[DataBlock] = []

    @property
    def datablocks(self) -> List[DataBlock]:
        if len(self._datablocks) == 0:
            for x in self.xnode.findall("db"):
                self._datablocks.append(DataBlock(x))
        return self._datablocks

    def datablocks_in_range(
            self, startaddr: str, endaddr: str) -> List[DataBlock]:
        result: List[DataBlock] = []
        starti = int(startaddr, 16)
        endi = int(endaddr, 16)
        for db in self.datablocks:
            if starti <= int(db.startaddr, 16) and int(db.endaddr, 16) <= endi:
                result.append(db)
        return result

    def __str__(self) -> str:
        return "\n".join(str(db) for db in self.datablocks)
