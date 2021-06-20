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

from typing import List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


@armregistry.register_tag("B", ARMOpcode)
class ARMBranch(ARMOpcode):
    """branch instruction.

    B<c> label
    B<c>.W label

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    args[1]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "Branch")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[1], xdata.xprs[0]]
        else:
            return []

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:x .

        xprs[0]: true condition
        xprs[1]: false condition
        xprs[2]: target address (absolute)

        or, if no conditions

        xprs[0]: target address (absolute)
        """

        if xdata.has_branch_conditions():
            return "if " + str(xdata.xprs[0]) + " then goto " + str(xdata.xprs[2])
        elif self.tags[1] in ["a", "unc"]:
            return "goto " + str(xdata.xprs[0])
        else:
            return "if ? goto " + str(xdata.xprs[0])
