# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
"""Superclass of a basic block for different architectures.

Subclasses:
 - ARMBlock
 - AsmBlock
 - MIPSBlock
"""

import hashlib
import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.Instruction import Instruction

from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.Function


class BasicBlock(ABC):

    def __init__(
            self,
            xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def baddr(self) -> str:
        _baddr = self.xnode.get("ba")
        if _baddr is None:
            raise UF.CHBError("Basic block address is missing from xml")
        return _baddr

    @property
    def last_instruction(self) -> Instruction:
        lastaddr = sorted(self.instructions.keys())[-1]
        return self.instructions[lastaddr]

    @property
    def has_return(self) -> bool:
        return self.last_instruction.is_return_instruction

    @property
    @abstractmethod
    def instructions(self) -> Mapping[str, Instruction]:
        ...

    @property
    @abstractmethod
    def call_instructions(self) -> Sequence[Instruction]:
        ...

    @property
    @abstractmethod
    def store_instructions(self) -> Sequence[Instruction]:
        ...

    def has_instruction(self, iaddr: str) -> bool:
        return iaddr in self.instructions

    def instruction(self, iaddr: str) -> Instruction:
        if iaddr in self.instructions:
            return self.instructions[iaddr]
        raise UF.CHBError("Instruction " + iaddr + " not found")

    def md5(self) -> str:
        m = hashlib.md5()
        for instr in self.instructions.values():
            m.update(instr.bytestring.encode("utf-8"))
        return m.hexdigest()

    @abstractmethod
    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            sp: bool = True) -> str:
        ...

    def __str__(self) -> str:
        return self.to_string()
