# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
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
#
# ------------------------------------------------------------------------------
"""MIPS assembly code."""

import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod
from typing import Dict, List, Mapping, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.Instruction import Instruction


class AssemblyInstruction(ABC):

    def __init__(self, iaddr: str, stat: str = ""):
        self._iaddr = iaddr
        self._stat = stat

    @property
    def iaddr(self) -> str:
        return self._iaddr

    @property
    def addr_i(self) -> int:
        return int(self._iaddr, 16)

    @property
    @abstractmethod
    def mnemonic(self) -> str:
        ...

    @property
    def is_block_entry(self) -> bool:
        return "B" in self._stat

    @property
    def is_function_entry(self) -> bool:
        return "F" in self._stat


class Assembly(ABC):

    def __init__(self, app: "AppAccess", xnode: ET.Element) -> None:
        self._app = app
        self.xnode = xnode

    @property
    @abstractmethod
    def instructions(self) -> Mapping[str, AssemblyInstruction]:
        ...

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Assembly code")
        for (ia, i) in sorted(self.instructions.items()):
            lines.append(ia + "  " + str(i))
        return "\n".join(lines)
