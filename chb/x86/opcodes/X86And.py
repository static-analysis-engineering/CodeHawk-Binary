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
    import chb.x86.X86Instruction
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("and", X86Opcode)
class X86And(X86Opcode):
    """AND dst, src

    args[0]: index of dst operand in x86 dictionary
    args[1]: index of src operand in x86 dictionary
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

    def annotation(self, xdata: InstrXData) -> str:
        """Different formats dependent on operands.

        1) stack realignment: "stack-realign", with number of bytes

        2) zero assignement: "a:v"

        3) rewrite register: "a:vxx"  (dst = src (register))

        4) general case: "a:vxxxx"

        vars[x]: lhs
        xprs[0]: src
        xprs[1]: dst-rhs
        xprs[2]: src & dst (syntactic)
        xprs[3]: src & dst (simplified)
        """

        if xdata.tags[0] == 'stack-realign':
            alignment = str(xdata.args[0])
            return 'align stack on ' + alignment + ' bytes'

        elif len(xdata.xprs) == 0:  # rhs is zero, result is zero
            lhs = str(xdata.vars[0])
            return lhs + ' = 0'

        elif len(xdata.xprs) == 1:  # dst = src, value is unchanged
            lhs = str(xdata.vars[0])
            rhs = str(xdata.xprs[1])
            return lhs + ' = ' + rhs + ' (unchanged)'

        else:
            lhs = str(xdata.vars[0])
            result = xdata.xprs[2]
            rresult = xdata.xprs[3]
            xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
            return lhs + ' = ' + xresult

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        if xdata.tags[0] == 'stack-realign':
            return []
        else:
            return [xdata.vars[0]]

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        if xdata.tags[0] == 'stack-realign':
            return []
        elif len(xdata.xprs) == 0:
            return []
        elif len(xdata.xprs) == 3:
            return [xdata.xprs[2]]
        elif len(xdata.xprs) == 5:
            return [xdata.xprs[4]]
        else:
            return []

    # --------------------------------------------------------------------------
    # Performs a bitwise AND operation on the destination (first) and source
    # (second) operands and stores the result in the destination operand
    # location.
    #
    # Flags affected:
    # The OF and CF flags are cleared; the SF, ZF, and PF flags are set according
    # to the result.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        dstop = self.dst_operand
        src1op = self.dst_operand
        src2op = self.src_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if src1val.is_doubleword and src1val.is_literal and src2val.is_literal:
            src1val = cast(SV.SimDoubleWordValue, src1val)
            src2val = cast(SV.SimLiteralValue, src2val)
            result = src1val.bitwise_and(src2val)
            simstate.set(iaddr, dstop, result)
            simstate.clear_flag(iaddr, 'OF')
            simstate.clear_flag(iaddr, 'CF')
            simstate.update_flag(iaddr, 'SF', result.is_negative)
            simstate.update_flag(iaddr, 'ZF', result.is_zero)
            simstate.update_flag(iaddr, 'PF', result.is_odd_parity)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Bitwise and not yet supported for "
                 + str(src1op)
                 + ":"
                 + str(src1val)
                 + ", "
                 + str(src2op)
                 + ":"
                 + str(src2val)))
