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


@mipsregistry.register_tag("jalr", MIPSOpcode)
class MIPSJumpLinkRegister(MIPSOpcode):
    """JALR rd, rs

    Jump and Link Register
    Execute a procedure call to an instruction address in a register.

    args[0]: index of rd in mips dictionary
    args[1]: index of rs in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(self, xdata: InstrXData) -> List[Dict[str, Any]]:
        return [x.to_annotated_value() for x in xdata.xprs]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def operand_values(self, xdata: InstrXData) -> Sequence[XXpr]:
        return self.arguments(xdata)

    def annotation(self, xdata: InstrXData) -> str:
        if xdata.has_call_target():
            args = ", ".join(str(x) for x in xdata.xprs)
            tgt = str(self.call_target(xdata))
            return "call " + tgt + "(" + args + ")"
        else:
            tgtx = str(xdata.xprs[0])
            return 'call* ' + tgtx

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if xdata.has_call_target():
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError(
                "Instruction does not have a call target: " + str(self))

    @property
    def tgt_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: temp <- GPR[rs]
    #      GPR[rd] <- PC + 8
    #   I+1: if Config1[CA] = 0 then
    #            PC <- temp
    #        else
    #            PC <- temp[GPRLEN-1..1] || 0
    #            ISAMode <- temp[0]
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        tgtop = self.tgt_operand
        tgtval = simstate.rhs(iaddr, tgtop)
        simra = SSV.pc_to_return_address(
            simstate.programcounter.add_offset(8), simstate.function_address)
        simstate.increment_programcounter()
        simstate.registers['ra'] = simra

        if tgtval.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "jalr: target address is undefined: " + str(tgtop))

        if tgtval.is_address:
            tgtval = cast(SSV.SimAddress, tgtval)
            if tgtval.is_global_address:
                tgtaddr = cast(SSV.SimGlobalAddress, tgtval)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "target address is not global: " + str(tgtval))

        # check if literal could be an address
        elif tgtval.is_literal:
            tgtaddr = simstate.resolve_literal_address(iaddr, tgtval.literal_value)
            if tgtaddr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "jalr: target address cannot be resolved: " + str(tgtval))

        elif tgtval.is_symbolic:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("symbolic target address not recognized: " + str(tgtval)))
        else:
            raise SU.CHBSimCallTargetUnknownError(
                simstate, iaddr, tgtval, 'target = ' + str(tgtval))

        simstate.simprogramcounter.set_delayed_programcounter(tgtaddr)
        return SU.simcall(iaddr, simstate, tgtaddr, simra)
