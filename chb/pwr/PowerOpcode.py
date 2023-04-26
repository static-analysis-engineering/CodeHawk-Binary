# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
"""Superclass for all Power opcodes."""

from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.pwr.PowerDictionaryRecord import PowerDictionaryRecord
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary


branch_opcodes: List[str] = []

call_opcodes: List[str] = []


class PowerOpcode(PowerDictionaryRecord):

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerDictionaryRecord.__init__(self, pwrd, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    def annotation(self, xdata: InstrXData) -> str:
        return self.__str__()

    @property
    def operands(self) -> List[PowerOperand]:
        """Return the operands that appear in the printed assembly instructions.

        Note that this is offten a subset of the operands present.
        """

        return []

    @property
    def opargs(self) -> List[PowerOperand]:
        """Return all operand types in the assembly instruction arguments.

        This excludes items in the operand list that are integers or booleans.
        """

        return []

    @property
    def operandstring(self) -> str:
        return ", ".join(str(op) for op in self.operands)

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        return []

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    def is_branch_instruction(self, xdata: InstrXData) -> bool:
        return self.tags[0] in branch_opcodes
    
    def is_return_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_jump_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return self.mnemonic in call_opcodes or xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> CallTarget:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return False

    def __str__(self) -> str:
        return self.tags[0] + ":pending"
