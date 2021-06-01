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


@x86registry.register_tag("sbb", X86Opcode)
class X86SubBorrow(X86Opcode):
    """SBB dst, src

    args[0]: index of dst in x86dictionary
    args[1]: index of src in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[0])

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[1])

    def get_operands(self) -> List[X86Operand]:
        return [self.dst_operand, self.src_operand]

    # xdata: [ "a:vxxxxxx" ; lhs, rhs1, rhs2, rhs1-rhs2, rhs1-rhs2-simplified,
    #                        rhs1-rhs2+1, rhs1-rhs2+1-simplified ]
    def get_annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxxxxx

        vars[0]: lhs
        xprs[0]: rhs1 (dst)
        xprs[1]: rhs2 (src)
        xprs[2]: rhs1 - rhs2 (syntactic)
        xprs[3]: (rhs1 - rhs2) + 1 (syntactic)
        xprs[4]: rhs1 - rhs2 (simplified)
        xprs[5]: (rhs1 - rhs2) + 2 (simplified)
        """
        
        lhs = str(xdata.vars[0])
        rhsx = xdata.xprs[2]
        rrhsx = xdata.xprs[3]
        xrhsx = simplify_result(xdata.args[3], xdata.args[4], rhsx, rrhsx)
        rhsx1 = xdata.xprs[4]
        rrhsx1 = xdata.xprs[5]
        xrhsx1 = simplify_result(xdata.args[5],xdata.args[6], rhsx1, rrhsx1)
        return (lhs + ' = ' + xrhsx + ' or ' + xrhsx1)

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Adds the source operand (second operand) and the carry (CF) flag, and
    # subtracts the result from the destination operand (first operand). The
    # result of the subtraction is stored in the destination operand.
    # When an immediate value is used as an operand, it is sign-extended to the
    # length of the destination operand format.
    # The SBB instruction does not distinguish between signed or unsigned
    # operands. Instead, the processor evaluates the result for both data types
    # and sets the OF and CF flags to indicate a borrow in the signed or
    # unsigned result, respectively. The SF flag indicates the sign of the
    # signed result.
    #
    # Flags affected:
    # The OF, SF, ZF, AF, PF, and CF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcop = self.src_operand
        dstop = self.dst_operand
        size = dstop.size
        srcval = simstate.get_rhs(iaddr, srcop)
        dstval = simstate.get_rhs(iaddr, dstop)        
        if srcval.is_literal() and dstval.is_literal() and dstval.is_doubleword():
            srcval = cast(SV.SimLiteralValue, srcval)
            dstval = cast(SV.SimDoubleWordValue, dstval)
            srcval = srcval.sign_extend(size)
            cflag = cast(SV.SimBoolValue, simstate.get_flag_value(iaddr, 'CF'))
            if not cflag.is_defined():
                result = SV.mk_undefined_simvalue(size)
                simstate.set(iaddr, dstop, result)
            else:
                cflagval = SV.mk_simvalue(cflag.value, size=size)
                xsrcval = srcval.add(cflagval)
                result = dstval.sub(xsrcval)
                simstate.set(iaddr, dstop, result)
                simstate.update_flag(iaddr, 'CF', dstval.sub_carries(srcval))
                simstate.update_flag(iaddr, 'OF', dstval.sub_overflows(srcval))
                simstate.update_flag(iaddr, 'SF', result.is_negative())
                simstate.update_flag(iaddr, 'ZF', result.is_zero())
                simstate.update_flag(iaddr, 'PF', result.is_odd_parity())
