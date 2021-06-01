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
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState    

@x86registry.register_tag("rcr", X86Opcode)
class X86RotateRightCF(X86Opcode):
    """RCR dst, src

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

    # xdata: [ "a:vxx" ],[ lhs, number of bits to rotate, value to rotate ]
    def get_annotation(self, xdata: InstrXData) -> str:
        """data format: a:vxx .

        vars[0]: dst
        xprs[0]: src
        xprs[1]: dst-rhs
        """
        
        lhs = str(xdata.vars[0])
        rhs1 = str(xdata.xprs[0])
        rhs2 = str(xdata.xprs[1])
        return lhs + ' = ' + rhs2 + ' rotate-right by ' + rhs1 + ' CF'

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # TBD: incorporate CF
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        dstval = simstate.get_rhs(iaddr, dstop)
        raise SU.CHBSimError(
            simstate,
            iaddr,
            ("Rcr not yet implemented for "
             + str(dstop)
             + ":"
             + str(dstval)
             + ", "
             + str(srcop)
             + ":"
             + str(srcval)))


