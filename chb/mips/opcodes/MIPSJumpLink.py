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
    from chb.api.CallTarget import CallTarget, AppTarget, StubTarget
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


@mipsregistry.register_tag("jal", MIPSOpcode)
class MIPSJumpLink(MIPSOpcode):
    """JAL target

    Jump and Link
    Execute a procedure call within the current 256MB-aligned region.

    args[0]: target
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
            raise UF.CHBError("Call target not found for " + str(self))

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in self.arguments(xdata)]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def annotation(self, xdata: InstrXData) -> str:
        cargs = ", ".join(str(x) for x in self.arguments(xdata))
        if self.has_call_target(xdata):
            tgt = self.call_target(xdata)
            if tgt.is_app_target:
                tgt = cast("AppTarget", tgt)
                return "call " + str(tgt.address) + "(" + cargs + ")"
            elif tgt.is_so_target:
                tgt = cast("StubTarget", tgt)
                return "call " + str(tgt) + "(" + cargs + ")"
            else:
                return "call " + str(self.target) + "(" + cargs + ")"
        else:
            return "call " + str(self.target) + "(" + cargs + ")"

    # ----------------------------------------------------------------------
    # Operation:
    #   I: GPR[31] <- PC + 8
    #   I+1: PC <- PC[GPRLEN..28] || instr_index || 0[2]
    # ----------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        tgtaddr = self.target.absolute_address_value
        tgt = SSV.mk_global_address(tgtaddr)
        returnaddr = SSV.mk_global_address(int(iaddr, 16) + 8)
        simstate.registers['ra'] = returnaddr
        simstate.increment_program_counter()
        simstate.set_delayed_program_counter(tgt)
        return SU.simcall(iaddr, simstate, tgt, returnaddr)
