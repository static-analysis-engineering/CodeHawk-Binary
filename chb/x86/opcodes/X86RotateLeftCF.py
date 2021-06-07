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

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("rcl", X86Opcode)
class X86RotateLeftCF(X86Opcode):
    """RCL dst, src

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
        return self.x86d.operand(self.args[0])

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand, self.src_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:vxx

        vars[0]: dst
        xprs[0]: src (number of bits to rotate)
        xprs[1]: dst-rhs  (value to rotate)
        """

        lhs = str(xdata.vars[0])
        rhs1 = str(xdata.xprs[0])
        rhs2 = str(xdata.xprs[2])
        return lhs + ' = ' + rhs2 + ' rotate-left-by' + rhs1 + ' CF'

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Rotates the bits of the first operand (destination operand) the number of
    # bit positions specified in the second operand (count operand) and stores
    # the result in the destination operand. The count operand is an unsigned
    # integer that can be an immediate or a value in the CL register. In legacy
    # and compatibility mode, the processor restricts the count to a number
    # between 0 and 31 by masking all the bits in the count operand except
    # the 5 least-significant bits.
    #
    # The otate through carry left (RCL) instruction shifts all the bits
    # toward more-significant bit positions, except for the most-significant
    # bit, which is rotated to the least-significant bit location.
    #
    # The RCL instruction includes the CF flag in the rotation. The RCL
    # instruction shifts the CF flag into the least-significant bit and shifts
    # the most-significant bit into the CF flag.
    #
    # The OF flag is defined only for the 1-bit rotates; it is undefined in all
    # other cases (except that a zero-bit rotate does nothing, that is affects
    # no flags). For left rotates, the OF flag is set to the exclusive OR of
    # the CF bit (after the rotate) and the most-significant bit of the result.
    # CASE size:
    #    8: tempcount = (count & 31) % 9
    #   16: tempcount = (count & 31) % 17
    #   32: tempcount = (count & 31)
    # WHILE tempcount != 0 DO:
    #   tempCF = msb(dest)
    #   dest = (dest * 2) + CF
    #   CF = tempCF
    #   tempcount = tempcount - 1
    # IF count == 1:
    #   OF = msb(dest) xor CF
    # ELSE:
    #   OF is undefined
    #
    # Flags affected:
    # The CF flag contains the value of the bit shifted into it. The OF flag
    # is affected only for single-bit rotates; it is undefined for multi-bit
    # rotates. The SF, ZF, AF, and PF flags are not affected.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcop = self.src_operand
        dstop = self.dst_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        dstval = simstate.get_rhs(iaddr, dstop)
        cflag = simstate.get_flag_value(iaddr, 'CF')
        if cflag is None:
            simstate.set(iaddr, dstop, SV.mk_undefined_simvalue(dstop.size))
        elif (dstval.is_literal
              and dstval.is_defined
              and srcval.is_literal
              and srcval.is_defined):
            dstval = cast(SV.SimLiteralValue, dstval)
            srcval = cast(SV.SimLiteralValue, srcval)
            (cflag, result) = dstval.bitwise_rcl(srcval, cflag)
            simstate.set(iaddr, dstop, result)
            if srcval.value > 0:
                simstate.update_flag(iaddr, 'CF', cflag == 1)
                if srcval.value == 1:
                    oflag = result.msb ^ cflag
                    simstate.update_flag(iaddr, 'OF', oflag == 1)
                else:
                    simstate.update_flag(iaddr, "OF", None)
