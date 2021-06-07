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


@x86registry.register_tag("ja", X86Opcode)
@x86registry.register_tag("jbe", X86Opcode)
@x86registry.register_tag("jc", X86Opcode)
@x86registry.register_tag("jg", X86Opcode)
@x86registry.register_tag("jge", X86Opcode)
@x86registry.register_tag("jl", X86Opcode)
@x86registry.register_tag("jle", X86Opcode)
@x86registry.register_tag("jnc", X86Opcode)
@x86registry.register_tag("jno", X86Opcode)
@x86registry.register_tag("jns", X86Opcode)
@x86registry.register_tag("jnz", X86Opcode)
@x86registry.register_tag("jo", X86Opcode)
@x86registry.register_tag("jpe", X86Opcode)
@x86registry.register_tag("jpo", X86Opcode)
@x86registry.register_tag("js", X86Opcode)
@x86registry.register_tag("jz", X86Opcode)
class X86Jcc(X86Opcode):
    """J<c> target.

    args[0]: index of target operand in x86dictionary
    """
    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def is_conditional_branch(self) -> bool:
        return True

    def has_predicate(self, xdata: InstrXData) -> bool:
        return len(xdata.xprs) > 0

    def predicate(self, xdata: InstrXData) -> XXpr:
        if len(xdata.xprs) > 0:
            return xdata.xprs[0]
        else:
            raise UF.CHBError("Conditional branch without expression")

    @property
    def target_address(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.target_address]

    def ft_conditions(self, xdata: InstrXData) -> List[XXpr]:
        if len(xdata.xprs) > 0:
            return [xdata.xprs[1], xdata.xprs[0]]
        else:
            return []

    # xdata: [ "a:x": branch predicate ]
    #        [ ]: no predicate found
    def annotation(self, xdata: InstrXData) -> str:

        # tgtaddr = str(self.target_address)
        tgtaddr = "tgt"
        if len(xdata.xprs) > 0:
            return 'if ' + str(xdata.xprs[0]) + ' goto ' + tgtaddr
        else:
            return 'if ? goto ' + tgtaddr

    # --------------------------------------------------------------------------
    # Checks the state of one or more of the status flags in the EFLAGS register
    # (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state
    # (condition), performs a jump to the target instruction specified by the
    # destination operand. A condition code (cc) is associated with each
    # instruction to indicate the condition being tested for. If the condition is
    # not satisfied, the jump is not performed and execution continues with the
    # instruction following the Jcc instruction.
    #
    # jc : jump if carry (CF = 1)
    # jnz: jump if not zero  (ZF = 0)
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        tag = self.tags[0]
        tgt = str(self.target_address)

        def jump() -> None:
            raise SU.CHBSimJumpException(iaddr, tgt)

        def fallthrough() -> None:
            raise SU.CHBSimFallthroughException(iaddr, tgt)

        def undefined(flag: str) -> None:
            raise UF.CHBError('Flag value ' + flag + ' is undefined')

        if tag == 'jc':
            cf = simstate.get_flag_value(iaddr, 'CF')
            if cf == 1:
                jump()
            elif cf == 0:
                fallthrough()
            else:
                undefined('CF')
        elif tag == 'jnz':
            zf = simstate.get_flag_value(iaddr, 'ZF')
            if zf == 0:
                jump()
            elif zf == 1:
                fallthrough()
            else:
                undefined('ZF')
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                'Conditional jump tag not yet supported: ' + tag)
