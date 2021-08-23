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

from typing import cast, List, TYPE_CHECKING

import chb.api.MIPSLinuxSyscalls as SC

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


@mipsregistry.register_tag("syscall 0", MIPSOpcode)
class MIPSSyscall(MIPSOpcode):
    """Cause a system call exception.

    args[0]: code field (bits 25:6)
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def code(self) -> int:
        return int(self.args[0])

    def arguments(self, xdata: InstrXData) -> List[XXpr]:
        if len(xdata.xprs) > 0:
            return xdata.xprs[:-1]
        else:
            return []

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if xdata.has_call_target():
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError(
                "Syscall instruction does not have a call target: "
                + str(self))

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:<v0><args><call-target-ix> , or a:<v0>

        xprs[0]: value of v0
        xprs[1...]: arguments
        xprs[-1]: index of call target in interface dictionary
        """

        if xdata.has_call_target():
            pargs = "(" + ", ".join(str(a) for a in self.arguments(xdata)) + ")"
            return str(xdata.call_target(self.ixd)) + pargs

        else:
            rhs = str(xdata.xprs[0])
            if rhs.startswith("0x"):
                syscallnumber = int(rhs, 16)
                syscallfunction = SC.get_mips_linux_syscall(syscallnumber)
                return "linux-systemcall:" + syscallfunction
            else:
                return "linux-systemcall(" + rhs + ")"

    # --------------------------------------------------------------------------
    # Operation:
    #    SignalException(SystemCall)
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        syscallindex = simstate.registers['v0']
        if syscallindex.is_literal and syscallindex.is_defined:
            syscallindex = cast(SV.SimLiteralValue, syscallindex)
            raise SU.CHBSimSystemCallException(
                simstate, iaddr, syscallindex.value)
        else:
            raise SU.CHBSimCallTargetUnknownError(
                simstate, iaddr, syscallindex, 'syscall = ' + str(syscallindex))
