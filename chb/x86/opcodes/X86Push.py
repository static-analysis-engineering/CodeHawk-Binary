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


@x86registry.register_tag("push", X86Opcode)
class X86Push(X86Opcode):
    """PUSH op

    args[0]: number of bytes
    args[1]: index of op in x86dictionary
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
    def src_operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[1])

    def get_operands(self) -> List[X86Operand]:
        return [self.src_operand]

    def get_opcode_operations(self) -> List[str]:
        src = self.src_operand
        dec = 'esp = esp-4'
        mem = 'mem[esp] = ' + src.to_operand_string()
        return [dec , mem]

    # xdata: [ "a:x"; "arg" ; callsite ],[ x, x, argindex ] function argument
    #        [ "a:v", "save" ] save initial value of register to the stack
    #        [ "a:vx" ] push operand to the stack
    def get_annotation(self, xdata: InstrXData) -> str:
        """data formats:
               1) a:xx, arg, callsite : function argument
               2) a:v, save : save initial value of register to the stack
               3) a:vx, otherwise

        1) xprs[0]: rhs
           xprs[1]: rhs (simplified)

        2) vars[0]: register variable being saved

        3) vars[0]: stack variable
           xprs[0]: rhs
        """

        if len(xdata.tags) == 3 and xdata.tags[1] == "arg":
            callsite = xdata.tags[2]
            argindex = xdata.args[2]
            xval = str(xdata.xprs[1])
            return "[" + str(callsite) + ":" + str(argindex) + ": " + xval + "]"


        elif len(xdata.tags) == 2 and xdata.tags[1] == "save":
            return "save " + str(xdata.vars[0])

        else:
            return str(xdata.vars[0]) + " := " + str(xdata.xprs[0])            

    def get_operand_values(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Decrements the stack pointer and then stores the source operand on the top
    # of the stack. if the address-size and operand-size attributes are 32, the
    # 32-bit ESP register (stack pointer) is decremented by 4. If both attributes
    # are 16, the 16-bit SP register (stack pointer) is decremented by 2.
    # If the source operand is an immediate and its size is less than the address
    # size of the stack, a sign-extended value is pushed on the stack. If the
    # source operand is the FS or GS and its size is less than the address size
    # of the stack, the zero-extended value is pushed on the stack.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcval = simstate.get_rhs(iaddr, self.src_operand)
        if srcval.is_literal():
            srcval = cast(SV.SimDoubleWordValue, srcval)
            simstate.push_value(iaddr, srcval.to_doubleword(signextend=True))
