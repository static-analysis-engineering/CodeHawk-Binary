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


@x86registry.register_tag("stosb", X86Opcode)
class X86Stos(X86Opcode):
    """STOSB dst, src

    args[0]: width
    args[1]: index of dst in x86dictionary
    args[2]: index of src in x86dictionary
    args[3]: index of edi in x86dictionary
    args[4]: index of direction flag in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def dst_operand(self) -> X86Operand:
        """Return the memory location pointed to by EDI."""
        
        return self.x86d.get_operand(self.args[1])   # (Edi)

    @property
    def src_operand(self) -> X86Operand:
        """Return AL, AX, EAX. """
        
        return self.x86d.get_operand(self.args[2])

    @property
    def edi_operand(self) -> X86Operand:
        """Return EDI. """

        return self.x86d.get_operand(self.args[3])

    @property
    def df_operand(self) -> X86Operand:
        """Return the direction flag."""

        return self.x86d.get_operand(self.args[4])

    @property
    def width(self) -> int:
        return self.args[0]

    def get_operands(self) -> List[X86Operand]:
        return [self.dst_operand, self.src_operand]

    # xdata: [ "a:vvxxxxxx": lhs, edilhs, rhs, rrhs, edirhs, redirhs, dfrhs, rdfrhs ]
    def get_annotation(self, xdata: InstrXData) -> str:
        """data format a:vvxxxxxx

        vars[0]: lhs
        vars[1]: edi-lhs
        xprs[0]: rhs
        xprs[1]: rhs (simplified)
        xprs[2]: edi-rhs
        xprs[3]: edi-rhs (simplified)
        xprs[4]: df
        xprs[5]: dr (simplified)
        """

        lhs = str(xdata.vars[0])
        edilhs = str(xdata.vars[1])
        rhs = str(xdata.xprs[1])
        edirhs = str(xdata.xprs[3])
        dfrhs = xdata.xprs[5]
        ediop = ' +/- '
        if dfrhs.is_int_const_value(0):
            ediop = ' + '
        elif dfrhs.is_int_const_value(1):
            ediop = ' - '
        return (
            lhs
            + ' = '
            + rhs
            + '; '
            + edilhs
            + ' = '
            +  edirhs
            + ediop
            + str(self.width)
            + ' (df = '
            + str(dfrhs)
            + ')')

    # --------------------------------------------------------------------------
    # Stores a byte, word, or doubleword from the AL, AX, or EAX register
    # (respectively) into the destination operand. The destination operand is a
    # memory location, the address of which is read from either the ES:EDI or
    # ES:DI register.
    #
    # After the byte, word, or doubleword is transferred from the register to
    # the memory location, the (E)DI register is incremented or decremented
    # according to the setting of the DF flag in the EFLAGS register. If the DF
    # flag is 0, the register is incremented; if the DF flag is 1, the register
    # is decremented (the register is incremented or decre- mented by 1 for
    # byte operations, by 2 for word operations, by 4 for doubleword
    # operations).
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self,iaddr: str, simstate: "X86SimulationState") -> None:
        dstop = self.dst_operand
        srcop = self.src_operand
        size = dstop.size
        ediop = self.edi_operand
        dfop = self.df_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        edival = simstate.get_rhs(iaddr, ediop)
        dfval = cast(SV.SimBoolValue, simstate.get_rhs(iaddr, dfop))
        ediinc = SV.mk_simvalue(4, size)
        if srcval.is_literal():
            srcval = cast(SV.SimLiteralValue, srcval)
            if dfval.is_set():
                edinewval = srcval.sub(ediinc)
            else:
                edinewval = srcval.add(ediinc)
            simstate.set(iaddr, dstop, srcval)            
            simstate.set(iaddr, ediop, edinewval)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Stosb not supported for src value: " + str(srcval))
        
