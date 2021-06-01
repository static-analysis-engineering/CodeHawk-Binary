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


@x86registry.register_tag("movsx", X86Opcode)
class X86Movs(X86Opcode):
    """MOVS dst, src

    move byte from address DS:[ESI] ro ES:[EDI]

    args[0]: size (1 or 4)
    args[1]: index of dst in x86dictionary
    args[2]: index of src in x86dictionary
    args[3]: index of esi in x86dictionary (srcptr)
    args[4]: index of edi in x86dictionary (dstptr)
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
    def src_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[2])

    @property
    def srcptr_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[3])

    @property
    def dstptr_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[4])

    def get_operands(self) -> List[X86Operand]:
        return [
            self.dst_operand,
            self.src_operand,
            self.srcptr_operand,
            self.dstptr_operand]

    # xdata: [ "a:vvvxxxxxx": lhs, srcptrlhs (esi), dsptrlhs (edi),
    #                         rhs, rhs-rewritten, srcptrrhs, srcptrrhs-rewritten,
    #                         dstptrrhs, dstptrrhs-rewritten ]
    def get_annotation(self, xdata: InstrXData) -> str:
        """data format: a:vvvxxxxxx .

        vars[0]: lhs (memory location)
        vars[1]: srcptrlhs (esi)
        vars[2]: dstptrlhs (edi)
        xprs[0]: rhs (memory location)
        xprs[1]: rhs (simplified)
        xprs[2]: srcptrrhs
        xprs[3]: srcptrrhs (simplified)
        xprs[4]: dstptrrhs
        xprs[5]: dstptrrhs (simplified
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[0]
        rrhs = xdata.xprs[1]
        xrhs = simplify_result(xdata.args[3], xdata.args[4], rhs, rrhs)
        srcptrrhs = xdata.xprs[2]
        rsrcptrrhs = xdata.xprs[3]
        xsrcptrrhs = simplify_result(
            xdata.args[5], xdata.args[6], srcptrrhs, rsrcptrrhs)
        dstptrrhs = xdata.xprs[4]
        rdstptrrhs = xdata.xprs[5]
        xdstptrrhs = simplify_result(
            xdata.args[7], xdata.args[8], dstptrrhs, rdstptrrhs)
        return (
            lhs
            + ' = '
            +  xrhs
            + '; esi = '
            + xsrcptrrhs
            + '; edi = '
            + xdstptrrhs)

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Moves the byte, word, or doubleword specified with the second operand
    # (source operand) to the location specified with the first operand
    # (destination operand). Both the source and destination operands are
    # located in memory. The address of the source operand is read from the
    # DS:ESI or the DS:SI registers (depending on the address-size attribute
    # of the instruction, 32 or 16, respectively). The address of the
    # destination operand is read from the ES:EDI or the ES:DI registers
    # (again depending on the address-size attribute of the instruction).
    #
    # After the move operation, the (E)SI and (E)DI registers are incremented or
    # decremented automatically according to the setting of the DF flag in the
    # EFLAGS register. (If the DF flag is 0, the (E)SI and (E)DI register are
    # incremented; if the DF flag is 1, the (E)SI and (E)DI registers are
    # decremented.) The registers are incremented or decremented by 1 for byte
    # operations, by 2 for word operations, or by 4 for double- word operations.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcop = self.src_operand
        dstop = self.dst_operand
        srcptrop = self.srcptr_operand
        dstptrop = self.dstptr_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        srcptrval = simstate.get_rhs(iaddr, srcptrop)
        dstptrval = simstate.get_rhs(iaddr, dstptrop)
        dflag = simstate.get_flag_value(iaddr, 'DF')
        incr = SV.mk_simvalue(srcptrop.size, self.size)
        simstate.set(iaddr, dstop, srcval)
        if (
                srcptrval.is_literal()
                and srcptrval.is_defined()
                and dstptrval.is_literal()
                and dstptrval.is_defined()):
            srcptrval = cast(SV.SimLiteralValue, srcptrval)
            dstptrval = cast(SV.SimLiteralValue, dstptrval)
            if dflag == 0:
                simstate.set(iaddr, srcptrop, srcptrval.add(incr))
                simstate.set(iaddr, dstptrop, dstptrval.add(incr))
            elif dflag == 1:
                simstate.set(iaddr, srcptrop, srcptrval.sub(incr))
                simstate.set(iaddr, dstptrop, dstptrval.sub(incr))
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    'Unexpected value for direction flag: ' + str(dflag))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Movs not supported for "
                 + str(srcptrop)
                 + ":"
                 + str(srcptrval)
                 + ", "
                 + str(dstptrop)
                 + ":"
                 + str(dstptrval)))
                             
            
