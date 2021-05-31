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

from typing import cast, List, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.simulation.X86SimulationState import X86SimulationState

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary

@x86registry.register_tag("cmp", X86Opcode)
class X86Compare(X86Opcode):

    # tags: [ 'cmp' ]
    # args: [ op1, op2 ]
    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def operand_1(self) -> X86Operand:
        return self.x86d.get_operand(self.args[0])

    @property
    def operand_2(self) -> X86Operand:
        return self.x86d.get_operand(self.args[1])

    def get_operands(self) -> List[X86Operand]:
        return [self.operand_1, self.operand_2]

    def get_annotation(self, xdata: InstrXData) -> str:
        return ''

    # --------------------------------------------------------------------------
    # Compares the first source operand with the second source operand and sets
    # the status flags in the EFLAGS register according to the results.
    # The comparison is performed by subtracting the second operand from the
    # first operand and then setting the status flags in the same manner as the
    # SUB instruction. When an immediate value is used as an operand, it is
    # sign-extended to the length of the first operand.
    #
    # Flags affected:
    # The CF, OF, SF, ZF, AF, and PF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: X86SimulationState) -> None:
        op1 = self.operand_1
        op2 = self.operand_2
        val1 = simstate.get_rhs(iaddr, op1)
        val2 = simstate.get_rhs(iaddr, op2)
        if val2.is_literal():
            val2 = cast(SV.SimLiteralValue, val2)
            if val2.is_byte():
                val2 = cast(SV.SimByteValue, val2)
                val2 = val2.sign_extend(op1.size)
            elif val2.is_word():
                val2 = cast(SV.SimWordValue, val2)
                val2 = val2.sign_extend(op1.size)
        if (
                val1.is_doubleword()
                and val1.is_literal()
                and val2.is_doubleword()
                and val2.is_literal()):
            val1 = cast(SV.SimDoubleWordValue, val1)
            val2 = cast(SV.SimDoubleWordValue, val2)
            result = val1.sub(val2)
            simstate.update_flag(iaddr, 'CF',val1.sub_carries(val2))
            simstate.update_flag(iaddr, 'OF',val1.sub_overflows(val2))
            simstate.update_flag(iaddr, 'SF',result.is_negative())
            simstate.update_flag(iaddr, 'ZF',result.is_zero())
            simstate.update_flag(iaddr, 'PF',result.is_odd_parity())
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Comparison of "
                 + str(op1)
                 + ":"
                 + str(val1)
                 + " and "
                 + str(op2)
                 + ":"
                 + str(val2)
                 + " not yet supported"))
        
