# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("MRC", ARMOpcode)
class ARMMoveRegisterCoprocessor(ARMOpcode):
    """Moves data from a coprocessor to a core register.

    MRC<c> <coproc>, <opc1>, <Rt>, <CRn>, <CRm>{, <opc2>}

    tags[1]: <c>
    args[0]: coproc
    args[1]: opc1
    args[2]: index of Rt in armdictionary
    args[3]: CRn
    args[4]: CRm
    args[5]: opc2
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 6, "MoveRegisterCoprocessor")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[2])]

    @property
    def operandstring(self) -> str:
        coproc = "p" + str(self.args[0])
        opc1 = str(self.args[1])
        crn = "c" + str(self.args[3])
        crm = "c" + str(self.args[4])
        opc2 = str(self.args[5])
        return (
            coproc
            + ", "
            + opc1
            + ", "
            + str(self.operands[0])
            + ", "
            + crn
            + ", "
            + crm
            + ", "
            + opc2)

    def annotation(self, xdata: InstrXData) -> str:
        """format a:v

        vars[0]: lhs; destination register (Rt)
        """

        lhs = str(xdata.vars[0])
        return lhs + " := ?"
