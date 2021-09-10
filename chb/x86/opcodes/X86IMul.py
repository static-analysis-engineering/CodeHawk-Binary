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


@x86registry.register_tag("imul", X86Opcode)
class X86IMul(X86Opcode):
    """IMUL dst, src, imm .

    args[0]: size (in bytes)
    args[1]: index of dst in x86dictionary
    args[2]: index of src1 in x86dictionary
    args[3]: index of src2 in x86dictionary
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
    def dst_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def src1_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[2])

    @property
    def src2_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[3])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand, self.src1_operand, self.src2_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxxx

        vars[0]: lhs
        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: product (syntactic)
        xprs[3]: product (simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[2]
        rrhs = xdata.xprs[3]
        xrhs = simplify_result(xdata.args[3], xdata.args[4], rhs, rrhs)
        return lhs + ' = ' + xrhs

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Performs a signed multiplication of two operands. When an immediate value
    # is used as an operand, it is sign-extended to the length of the destination
    # operand format. The result is truncated to the length of the destination
    # before it is stored in the destination register.
    #
    # The CF and OF flags are set when significant bit (including the sign bit)
    # are carried into the upper half of the result. The CF and OF flags are
    # cleared when the result (including the sign bit) fits exactly in the lower
    # half of the result.
    #
    # Flags affected:
    # For the one operand form of the instruction, the CF and OF flags are set
    # when signif- icant bits are carried into the upper half of the result and
    # cleared when the result fits exactly in the lower half of the result. For
    # the two- and three-operand forms of the instruction, the CF and OF flags
    # are set when the result must be truncated to fit in the destination operand
    # size and cleared when the result fits exactly in the destination operand
    # size. The SF, ZF, AF, and PF flags are undefined.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        src1op = self.src1_operand
        src2op = self.src2_operand
        dstop = self.dst_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if (
                src1val.is_literal
                and src1val.is_defined
                and src1val.is_doubleword
                and src2val.is_literal
                and src2val.is_defined
                and src2val.is_doubleword):
            src1val = cast(SV.SimDoubleWordValue, src1val)
            src2val = cast(SV.SimDoubleWordValue, src2val)
            src2val = src2val.sign_extend(self.size)
            result = src1val.mul(src2val)
            lowresult = result.lowhalf
            highresult = result.highhalf
            if dstop.size < (result.width // 8):
                simstate.set(iaddr, dstop, lowresult)
            else:
                simstate.set(iaddr, dstop, result)
            simstate.update_flag(iaddr, 'CF', not highresult.is_zero)
            simstate.update_flag(iaddr, 'OF', not highresult.is_zero)
            simstate.undefine_flag(iaddr, 'SF')
            simstate.undefine_flag(iaddr, 'ZF')
            simstate.undefine_flag(iaddr, 'PF')
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Mul values are not literal: "
                 + str(src1val)
                 + ", "
                 + str(src2val)))
