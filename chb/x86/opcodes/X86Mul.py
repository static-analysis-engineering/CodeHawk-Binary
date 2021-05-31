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


@x86registry.register_tag("mul", X86Opcode)
class X86Mul(X86Opcode):
    """MUL dst, src1, src2

    args[0]: operand size (in bytes)
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
        return self.x86d.get_operand(self.args[1])

    @property
    def src1_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[2])

    @property
    def src2_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[3])

    def get_operands(self) -> List[X86Operand]:
        return [self.dst_operand, self.src1_operand, self.src2_operand]

    def get_annotation(self, xdata: InstrXData) -> str:
        """data format

        vars[0]: lhs
        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: rhs1 * rhs2 (syntactic)
        xprs[3]: rhs1 * rhs2 (simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[2]
        rrhs = xdata.xprs[3]
        xrhs = simplify_result(xdata.args[3], xdata.args[4], rhs, rrhs)
        return lhs + ' = ' + xrhs

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Performs an unsigned multiplication of the first operand (destination
    # operand) and the second operand (source operand) and stores the result
    # in the destination operand. The destination operand is an implied operand
    # located in register AL, AX or EAX (depending on the size of the operand);
    # the source operand is located in a general-purpose register or a memory
    # location.
    #
    # The result is stored in register AX, register pair DX:AX, or register pair
    # EDX:EAX (depending on the operand size), with the high-order bits of the
    # product contained in register AH, DX, or EDX, respectively. If the high-order
    # bits of the product are 0, the CF and OF flags are cleared; otherwise,
    # the flags are set.
    #
    # Flags affected:
    # The OF and CF flags are set to 0 if the upper half of the result is 0;
    # otherwise, they are set to 1. The SF, ZF, AF, and PF flags are undefined.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        src1op = self.src1_operand
        src2op = self.src2_operand
        dstop = self.dst_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if src1val.is_literal() and src1val.is_doubleword() and src2val.is_literal():
            src1val = cast(SV.SimDoubleWordValue, src1val)
            src2val = cast(SV.SimLiteralValue, src2val)
            result = src1val.mul(src2val)
            simstate.set(iaddr, dstop, result)
            highresult = result.highhalf
            simstate.update_flag(iaddr, 'CF', not highresult.is_zero())
            simstate.update_flag(iaddr, 'OF', not highresult.is_zero())
            simstate.undefine_flag(iaddr, 'SF')
            simstate.undefine_flag(iaddr, 'ZF')
            simstate.undefine_flag(iaddr, 'PF')
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Multiplication not yet supported for " + str(src1val))

    
