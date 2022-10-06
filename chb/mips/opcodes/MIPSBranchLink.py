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
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
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


@mipsregistry.register_tag("bal", MIPSOpcode)
class MIPSBranchLink(MIPSOpcode):
    """BAL offset

    Branch and Link.
    Do an unconditional PC-relative procedure call.

    args[0]: index of offset in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.target]

    @property
    def target(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    def has_call_target(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if xdata.has_call_target():
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError(
                "Instruction does not have a call target: " + str(self))

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        args = self.arguments(xdata)
        if args:
            return any([x.is_string_reference for x in self.arguments(xdata)])
        else:
            return False

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        args = self.arguments(xdata)
        if args:
            return any([x.is_stack_address for x in self.arguments(xdata)])
        else:
            return False

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in self.arguments(xdata)]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def annotation(self, xdata: InstrXData) -> str:
        args = ", ".join(str(x) for x in self.arguments(xdata))
        if xdata.has_call_target():
            return "call " + str(xdata.call_target(self.ixd)) + "(" + args + ")"
        else:
            return "call- " + str(self.target) + "(" + args + ")"

    # --------------------------------------------------------------------------
    # Operation:
    #    I:    target_offset <- sign_extend(offset || 0[2])
    #          GPR[31] <- PC + 8
    #    I+1:  PC <- PC + target_offset
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        tgtop = self.target
        tgtaddr = tgtop.absolute_address_value
        tgt = simstate.resolve_literal_address(iaddr, tgtaddr)
        simstate.increment_programcounter()
        returnaddr = SSV.pc_to_return_address(
            simstate.programcounter.add_offset(4), simstate.function_address)
        simstate.registers["ra"] = returnaddr
        simstate.simprogramcounter.set_delayed_programcounter(tgt)
        return SU.simcall(iaddr, simstate, tgt, returnaddr)
