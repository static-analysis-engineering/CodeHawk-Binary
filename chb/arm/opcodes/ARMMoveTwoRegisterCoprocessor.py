# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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


@armregistry.register_tag("MRRC", ARMOpcode)
class ARMMoveTwoRegisterCoprocessor(ARMOpcode):
    """Moves data from a coprocessor to two core registers.

    MRRC<c> <coproc>, <opc>, <Rt>, <Rt2>, <CRm>

    tags[1]: <c>
    args[0]: coproc
    args[1]: opc
    args[2]: index of Rt in armdictionary
    args[3]: index of Rt2 in armdictionary
    args[4]: CRm
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "MoveTwoRegisterCoprocessor")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [2, 3]]

    def annotation(self, xdata: InstrXData) -> str:
        """format a:vv

        vars[0]: lhs; destination register (Rt)
        vars[1]: lhs: destination register (Rt2)
        """

        lhs = str(xdata.vars[0])
        lhs2 = str(xdata.vars[1])
        return lhs + " := ?; " + lhs + " := ?"
