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
"""ARM opcodes."""

from typing import List, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord
from chb.arm.ARMOperand import ARMOperand

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.simulation.SimulationState import SimulationState


def simplify_result(id1: int, id2: int, x1: XXpr, x2: XXpr) -> str:
    if id1 == id2:
        return str(x1)
    else:
        return str(x1) + ' (= ' + str(x2) + ')'


branch_opcodes = [
    "B", "BX"
]


extensions = {
    "eq": "EQ",
    "ne": "NE",
    "cs": "CS",
    "cc": "CC",
    "neg": "MI",
    "nneg": "PL",
    "ov": "VS",
    "nov": "VC",
    "uh": "HI",
    "nuh": "LS",
    "ge": "GE",
    "lt": "LT",
    "gt": "GT",
    "le": "LE",
    "a": "",
    "unc": ""
    }


def get_extension(e: str) -> str:
    if e in extensions:
        return extensions[e]
    else:
        return e


class ARMOpcode(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    def annotation(self, xdata: InstrXData) -> str:
        return self.__str__()

    def mnemonic_extension(self) -> str:
        if self.mnemonic.startswith("IT"):
            return ""
        elif len(self.tags) > 1:
            return get_extension(self.tags[1])
        else:
            return ""

    @property
    def operands(self) -> List[ARMOperand]:
        return []

    @property
    def operandstring(self) -> str:
        return ", ".join(str(op) for op in self.operands)

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        """Return lhs variables."""
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        """Return rhs expressions."""
        return xdata.xprs

    @property
    def is_branch_instruction(self) -> bool:
        return self.tags[0] in branch_opcodes

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> CallTarget:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return False

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        raise SU.CHBSimError(
            simstate,
            iaddr,
            ("Simulation not yet supported for "
             + str(self)
             + " at address "
             + str(iaddr)))

    def __str__(self) -> str:
        return self.tags[0] + ":pending"
