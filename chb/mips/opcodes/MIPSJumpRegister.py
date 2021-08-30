# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from typing import Any, cast, Dict, List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.invariants.XXpr import XXpr

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import (
    MIPSOpcode, simplify_result, get_jump_table_targets)
from chb.mips.MIPSOperand import MIPSOperand

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("jr", MIPSOpcode)
class MIPSJumpRegister(MIPSOpcode):
    """JR rs

    Jump Register.
    Execute a branch to an instruction address in a register.

    args[0]: index of rs in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.target]

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in xdata.xprs]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) == 2 and xdata.tags[1] == "call"

    def is_jump_table(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) == 2 and xdata.tags[1] == "table"

    def annotation(self, xdata: InstrXData) -> str:
        """data formats: call, jumptable, indirect jump

        call: [a:..., 'call'], <args> + <index of call-target in ixd>
        jumptable: [a:x, 'table'], [xpr, [< i, address index>]]
        indirect jump: [a:x], [ xpr ]
        """

        if self.is_call(xdata) and xdata.has_call_target():
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"

        elif self.is_jump_table(xdata):
            tgtd = get_jump_table_targets([str(i) for i in xdata.args[1:]])
            tgtstr = ' ('
            for t in sorted(tgtd):
                tgtaddr = self.mipsd.app.bdictionary.address(int(t))
                tgtstr += (str(tgtd[t]) + ':' + str(tgtaddr) + ',')
            tgtstr += ')'
            jtgts = tgtstr
        else:
            jtgts = ''
        tgtx = str(xdata.xprs[0])
        return 'jmp* ' + tgtx + '  ' + jtgts + ' (' + str(self.src_operand) + ')'

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    @property
    def target(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    I: temp <- GPR[rs]
    #    I+1: if Config1[CA] = 0 then
    #            PC <- temp
    #         else
    #            PC <- temp[GPRLEN-1..1] || 0
    #         endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        srcval = simstate.rhs(iaddr, self.src_operand)
        simstate.increment_programcounter()

        if srcval.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "jr: jump target is undefined: " + str(srcval))

        elif srcval.is_symbol:
            if str(srcval).endswith("ra_in"):
                simstate.trace.add_delayed("\n")
                return "return"
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "jr: internal error: symbolic return address: " + str(srcval))

        elif srcval.is_function_return_address:
            addr = cast(SSV.SimReturnAddress, srcval)
            simstate.simprogramcounter.set_delayed_programcounter(addr)
            simstate.trace.add_delayed("\n")
            simstate.set_function_address(addr.functionaddr)
            return "return to " + addr.functionaddr

        elif srcval.is_global_address:
            gaddr = cast(SSV.SimGlobalAddress, srcval)
            simstate.simprogramcounter.set_delayed_programcounter(gaddr)
            simstate.trace.add_delayed("\n")
            simstate.set_function_address(hex(gaddr.offsetvalue))
            return "goto " + str(gaddr)

        elif srcval.is_literal:
            gaddr = simstate.resolve_literal_address(iaddr, srcval.literal_value)
            if gaddr.is_defined:
                simstate.simprogramcounter.set_delayed_programcounter(gaddr)
                return "goto " + str(gaddr)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "jr: target address cannot be resolved: " + str(srcval))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "jr: illegal target address: " + str(srcval))
