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


@armregistry.register_tag("MLA", ARMOpcode)
class ARMMultiplyAccumulate(ARMOpcode):
    """Multiplies two values and adds the value of a third register.

    MLA<c> <Rd>, <Rn>, <Rm>, <Ra>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: index of Rn in armdictionary
    args[2]: index of Rm in armdictionary
    args[3]: index of Ra in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "MultiplyAccumulate")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxxxxxx

        vars[0]: lhs1 (Rd)
        xprs[0]: rhs1 (Rn)
        xprs[1]: rhs2 (Rm)
        xprs[2]: rhsra (Ra)
        xprs[3]: (rhs1 * rhs2)
        xprs[4]: (rhs1 * rhs2) (simplified)
        xprs[5]: (rhsra + (rhs1 * rhs2))
        xprs[6]: (rhsra + (rhs1 * rhs2)) (simplified)
        """

        lhs = str(xdata.vars[0])
        lhsra = str(xdata.vars[1])
        prod = xdata.xprs[3]
        rprod = xdata.xprs[4]
        xprod = simplify_result(xdata.args[4], xdata.args[5], prod, rprod)
        xsum = xdata.xprs[5]
        rxsum = xdata.xprs[6]
        xxsum = simplify_result(xdata.args[6], xdata.args[7], xsum, rxsum)
        return (
            lhs
            + " := "
            + xprod
            + "; "
            + lhsra
            + " := "
            + xxsum)
