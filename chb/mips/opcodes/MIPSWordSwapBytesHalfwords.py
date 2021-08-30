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

from typing import cast, List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
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
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("wsbh", MIPSOpcode)
class MIPSWordSwapBytesHalfwords(MIPSOpcode):
    """Word Swap Bytes Within Halfwords.

    To swap the bytes within each halfword of GPR rt and store the value in GPR rd.

    args[0]: index of dst in mips dictionary
    args[1]: index of src in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxx

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs rewritten
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        return lhs + ' := ' + rhs

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   GPR[rd] <- GPR[r][23..16] || GPR[r][31..24] || GPR[r][7..0] || GPR[r][15..8]
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop)

        result: SV.SimValue
        if srcval.is_undefined:
            result = SV.simUndefinedDW

        if srcval.is_global_address:
            val = cast(SV.SimDoubleWordValue, SV.mk_simvalue(srcval.literal_value))
            srcval = cast(SSV.SimGlobalAddress, srcval)
            name = srcval.modulename
            resultval = val.swap_bytes_within_halfwords()
            result = SSV.mk_global_address(resultval.literal_value, name)

        elif srcval.is_literal:
            val = cast(SV.SimDoubleWordValue, srcval)
            result = val.swap_bytes_within_halfwords()

        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "wsbh: operand not recognized: " + str(srcop) + ": " + str(srcval))

        lhs = simstate.set(iaddr, dstop, result)
        simstate.increment_programcounter()
        return SU.simassign(iaddr, simstate, lhs, result, intermediates=str(srcval))
