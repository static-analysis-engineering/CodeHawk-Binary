# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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

from typing import List, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMSignedMultiplyLongXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vlo(self) -> "XVariable":
        return self.var(0, "vlo")

    @property
    def vhi(self) -> "XVariable":
        return self.var(1, "vhi")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def loresult(self) -> "XXpr":
        return self.xpr(2, "loresult")

    @property
    def hiresult(self) -> "XXpr":
        return self.xpr(3, "hiresult")

    @property
    def loresultr(self) -> "XXpr":
        return self.xpr(4, "loresultr")

    @property
    def hiresultr(self) -> "XXpr":
        return self.xpr(5, "hiresultr")

    @property
    def resultlo_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[2], self.xdata.args[4], self.loresult, self.loresultr)

    @property
    def resulthi_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[5], self.xdata.args[7], self.hiresult, self.hiresultr)

    @property
    def annotation(self) -> str:
        assignment1 = str(self.vlo) + " := " + self.resultlo_simplified
        assignment2 = str(self.vhi) + " := " + self.resulthi_simplified
        return self.add_instruction_condition(assignment1 + "; " + assignment2)


@armregistry.register_tag("SMULL", ARMOpcode)
class ARMSignedMultiplyLong(ARMOpcode):
    """Multiplies two signed 32-bit signed values to produce a 64-bit result

    SMULL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: flags are set
    args[1]: index of RdLo in armdictionary
    args[2]: index of RdHi in armdictionary
    args[3]: index of Rn in armdictionary
    args[4]: index of Rm in armdictionary
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "SignedMultiplyLong")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMSignedMultiplyLongXData(xdata)
        if xd.is_ok:
            return xd.annotation
        else:
            return "Error value"
