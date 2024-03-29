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

from typing import List, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("pusha", X86Opcode)
class X86PushRegisters(X86Opcode):
    """PUSHA. """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    def get_annotation(self, xdata: InstrXData) -> str:
        return 'push eax,ecx,edx,ebx,esp,ebp,esi,edi'

    # --------------------------------------------------------------------------
    # Pushes the contents of the general-purpose registers onto the stack. The
    # registers are stored on the stack in the following order: EAX, ECX, EDX,
    # EBX, ESP (original value), EBP, ESI, and EDI (if the current operand-size
    # attribute is 32) and AX, CX, DX, BX, SP (original value), BP, SI, and DI
    # (if the operand-size attribute is 16).
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        espval = simstate.get_regval(iaddr, 'esp')
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'eax'))
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'ecx'))
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'edx'))
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'ebx'))
        simstate.push_value(iaddr, espval)
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'ebp'))
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'esi'))
        simstate.push_value(iaddr, simstate.get_regval(iaddr, 'edi'))
