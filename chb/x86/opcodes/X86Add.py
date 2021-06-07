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

from typing import cast, List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("add", X86Opcode)
class X86Add(X86Opcode):
    """ADD dst, src

    args[0]: index of dst operand in x86dictionary
    args[1]: index of src operand in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand, self.src_operand]

    def opcode_operations(self) -> List[str]:
        src = self.src_operand.to_operand_string()
        dst = self.dst_operand.to_operand_string()
        return [dst + ' = ' + dst + ' + ' + src]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:vxxxx .

        vars[0]: dst-lhs
        xprs[0]: src
        xprs[1]: dst-rhs
        xprs[2]: src + dst (syntactic)
        xprs[3]: src + dst (simplified)
        """
        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return lhs + ' := ' + xresult

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        if len(xdata.xprs) > 2:
            return [xdata.vars[0]]
        else:
            return []

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        if len(xdata.xprs) > 2:
            return [xdata.xprs[3]]
        else:
            return []

    def operand_values(self, xdata: InstrXData) -> Sequence[XXpr]:
        return [xdata.xprs[0], xdata.xprs[1]]

    # --------------------------------------------------------------------------
    # Adds the destination operand (first operand) and the source operand
    # (second operand) and then stores the result in the destination operand.
    # When an immediate value is used as an operand, it is sign- extended to
    # the length of the destination operand format.
    # The ADD instruction performs integer addition. It evaluates the result
    # for both signed and unsigned integer operands and sets the OF and CF
    # flags to indicate a carry (over- flow) in the signed or unsigned result,
    # respectively. The SF flag indicates the sign of the signed result.
    #
    # Flags affected:
    # The OF, SF, ZF, AF, CF, and PF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        dstop = self.dst_operand
        src1op = self.dst_operand
        src2op = self.src_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if src1val.is_doubleword and src1val.is_literal:
            src1val = cast(SV.SimDoubleWordValue, src1val)
            result = src1val.add(src2val)
            simstate.set(iaddr, dstop, result)
            simstate.update_flag(iaddr, 'CF', src1val.add_carries(src2val))
            simstate.update_flag(iaddr, 'OF', src1val.add_overflows(src2val))
            simstate.update_flag(iaddr, 'SF', result.is_negative)
            simstate.update_flag(iaddr, 'ZF', result.is_zero)
            simstate.update_flag(iaddr, 'PF', result.is_odd_parity)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Addition not yet supported for "
                 + str(src1op)
                 + ":"
                 + str(src1val)
                 + ", "
                 + str(src2op)
                 + ":"
                 + str(src2val)))
