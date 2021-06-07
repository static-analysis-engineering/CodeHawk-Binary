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


@x86registry.register_tag("loop", X86Opcode)
class X86Loop(X86Opcode):
    """LOOP op

    args[0]: index of op in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def target_address(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.target_address]

    def annotation(self, xdata: InstrXData) -> str:
        return 'loop ' + str(self.target_address)

    # --------------------------------------------------------------------------
    # Performs a loop operation using the ECX or CX register as a counter
    # (depending on whether address size is 32 bits, or 16 bits).
    #
    # Each time the LOOP instruction is executed, the count register is
    # decremented, then checked for 0. If the count is 0, the loop is terminated
    # and program execution continues with the instruction following the LOOP
    # instruction. If the count is not zero, a near jump is performed to the
    # destination (target) operand, which is presumably the instruction at the
    # beginning of the loop.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        ecxval = simstate.get_regval(iaddr, 'ecx')
        if ecxval.is_literal:
            ecxval = cast(SV.SimLiteralValue, ecxval)
            newval = ecxval.sub(SV.simOne)
            simstate.set_register(iaddr, 'ecx', newval)
            tgtaddr = str(self.target_address)
            if newval.value != 0:
                raise SU.CHBSimJumpException(iaddr, tgtaddr)
            raise SU.CHBSimFallthroughException(iaddr, tgtaddr)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Loop cannot be applied to " + str(ecxval))
