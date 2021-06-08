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
"""Abstract superclass of an assembly instruction in different architectures.

Subclasses:
 - ARMInstruction
 - AsmInstruction
 - MIPSInstruction
"""

import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod

from typing import Callable, Dict, List, Optional, Sequence, TYPE_CHECKING

from chb.app.FunctionDictionary import FunctionDictionary

from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.Operand import Operand
    from chb.app.StackPointerOffset import StackPointerOffset
    from chb.invariants.XXpr import XXpr


class Instruction(ABC):

    def __init__(
            self,
            xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def iaddr(self) -> str:
        _iaddr = self.xnode.get("ia")
        if _iaddr is None:
            raise UF.CHBError("Instruction address is missing from xml")
        return _iaddr

    @property
    @abstractmethod
    def mnemonic(self) -> str:
        ...

    @property
    @abstractmethod
    def opcodetext(self) -> str:
        ...

    @property
    @abstractmethod
    def operands(self) -> Sequence["Operand"]:
        ...

    @property
    @abstractmethod
    def annotation(self) -> str:
        ...

    @property
    @abstractmethod
    def stackpointer_offset(self) -> "StackPointerOffset":
        ...

    @property
    @abstractmethod
    def bytestring(self) -> str:
        ...

    @property
    @abstractmethod
    def strings_referenced(self) -> Sequence[str]:
        ...

    @property
    @abstractmethod
    def is_call_instruction(self) -> bool:
        ...

    @property
    @abstractmethod
    def is_return_instruction(self) -> bool:
        ...

    @property
    @abstractmethod
    def call_arguments(self) -> Sequence["XXpr"]:
        ...

    @property
    @abstractmethod
    def is_branch_instruction(self) -> bool:
        ...

    @property
    @abstractmethod
    def ft_conditions(self) -> Sequence[XXpr]:
        ...

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
