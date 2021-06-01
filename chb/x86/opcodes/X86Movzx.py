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


@x86registry.register_tag("movzx", X86Opcode)
class X86Movzx(X86Opcode):
    """MOVZX dst, src

    args[0]: size of destination operand
    args[1]: index of dst in x86dictionary
    args[2]: index of src in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def size(self) -> int:
        return int(self.args[0])

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[2])

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[1])

    def get_operands(self) -> List[X86Operand]:
        return [self.dst_operand, self.src_operand]

    def get_annotation(self, xdata: InstrXData) -> str:
        """data format a:vxx

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs (simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[0]
        rrhs = xdata.xprs[1]
        xrhs = simplify_result(xdata.args[1], xdata.args[2], rhs, rrhs)
        return lhs + ' = ' + xrhs

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Copies the contents of the source operand (register or memory location) to
    # the desti- nation operand (register) and zero extends the value.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        if srcval.is_literal() and srcval.is_defined():
            srcval = cast(SV.SimLiteralValue, srcval)
            srcval = srcval.zero_extend(dstop.size)
            simstate.set(iaddr, dstop, srcval)
        raise SU.CHBSimError(
            simstate,
            iaddr,
            "Unable to zero extend non-literal value: " + str(srcval))

