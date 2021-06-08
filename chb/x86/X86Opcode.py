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
"""X86 Opcode specializations."""

from typing import List, Sequence, TYPE_CHECKING

from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import X86DictionaryRecord

if TYPE_CHECKING:
    import chb.x86.X86Dictionary
    import chb.x86.X86Operand
    from chb.x86.simulation.X86SimulationState import X86SimulationState


def simplify_result(id1: int, id2: int, x1: XXpr, x2: XXpr) -> str:
    if id1 == id2:
        return str(x1)
    else:
        return str(x1) + ' (= ' + str(x2) + ')'


class X86Opcode(X86DictionaryRecord):

    def __init__(
            self,
            x86d: "chb.x86.X86Dictionary.X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86DictionaryRecord.__init__(self, x86d, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    @property
    def is_return(self) -> bool:
        return False

    def has_return_expr(self) -> bool:
        return False

    def return_expr(self, xdata: InstrXData) -> XXpr:
        raise UF.CHBError("Abstract method return_expr")

    @property
    def is_conditional_branch(self) -> bool:
        return False

    @property
    def is_indirect_jump(self) -> bool:
        return False

    @property
    def is_call(self) -> bool:
        return False

    def has_predicate(self, xdata: InstrXData) -> bool:
        return False

    def predicate(self, xdata: InstrXData) -> XXpr:
        raise UF.CHBError("Abstract method predicate")

    def is_dll_call(self, xdata: InstrXData) -> bool:
        return False

    def is_so_call(self, xdata: InstrXData) -> bool:
        return False

    def is_app_call(self, xdata: InstrXData) -> bool:
        return False

    def is_unresolved_call(self, xdata: InstrXData) -> bool:
        return False

    @property
    def operands(self) -> Sequence["chb.x86.X86Operand.X86Operand"]:
        """Returns the syntactic operands."""
        return []

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        """Returns the lhs variables of an assignment if this is an assignment."""
        return []

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        """Returns the rhs exprs of an assignment if this is an assignment."""
        return []

    def annotation(self, xdata: InstrXData) -> str:
        """Annotation of assembly instruction.

        Combines general original opcode operands from (tags,args) with generated
        (inferred) operand data from xdata to create a description of the
        instruction.
        """
        return self.__str__()

    def opcode_operations(self) -> Sequence[str]:
        return []

    # return rhs-values of operands
    def operand_values(self, xdata: InstrXData) -> Sequence[XXpr]:
        return []

    def ft_conditions(self, xdata: InstrXData) -> List[XXpr]:
        return []

    def selector_expr(self, xdata: InstrXData) -> XXpr:
        raise UF.CHBError("Abstract method get_selector_expr")

    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        raise SU.CHBSimError(
            simstate,
            iaddr,
            ('Simulation not yet supported for ' + str(self)
             + ' at address ' + str(iaddr)))

    def __str__(self) -> str:
        return self.tags[0] + ':pending'
