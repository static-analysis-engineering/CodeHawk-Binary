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

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState    


@x86registry.register_tag("mov", X86Opcode)
class X86Mov(X86Opcode):
    """MOV dst, src

    args[0]: index of dst in x86dictionary
    args[1]: index of src in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[2])

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[1])

    def get_operands(self) -> List[X86Operand]:
        return [self.dst_operand, self.src_operand]

    def get_opcode_operations(self) -> List[str]:
        src = self.src_operand
        dst = self.dst_operand
        return [dst.to_operand_string() + ' = ' + src.to_operand_string()]

    # xdata: [ "nop" ]  no state change
    #        [ "a:xx" ; "arg", callsite ],[ x, x, argindex ] function argument
    #        [ "a:vxx" ]  assignment (lhs, rhs, rhs-simplified)
    def get_annotation(self, xdata: InstrXData) -> str:
        """data format: """

        if len(xdata.tags) > 1 and xdata.tags[1] == 'arg':
            callsite = xdata.tags[1]
            argindex = xdata.args[2]
            xval = str(xdata.xprs[1])
            return '[' + str(callsite) + ':' + str(argindex) + ': ' + xval + ']'
        if len(xdata.xprs) == 2:
            lhs = str(xdata.vars[0])
            rhs = xdata.xprs[0]
            rrhs = xdata.xprs[1]
            xrhs = simplify_result(xdata.args[1], xdata.args[2], rhs, rrhs)
            return lhs + ' = ' + xrhs
        else:
            if len(xdata.tags) > 0:
                return xdata.tags[0]
            else:
                return 'mov:????'

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    def get_operand_values(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Copies the second operand (source operand) to the first operand
    # (destination operand).
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcval = simstate.get_rhs(iaddr, self.src_operand)
        simstate.set(iaddr, self.dst_operand, srcval)
