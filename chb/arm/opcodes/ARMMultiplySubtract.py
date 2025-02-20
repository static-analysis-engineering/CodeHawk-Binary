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

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMMultiplySubtractXData(ARMOpcodeXData):
    """MLS <rd>, <rn>, <rm>, <ra>"""

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def xra(self) -> "XXpr":
        return self.xpr(2, "xra")

    @property
    def xprod(self) -> "XXpr":
        return self.xpr(3, "xprod")

    @property
    def xxprod(self) -> "XXpr":
        return self.xpr(4, "xxprod")

    @property
    def xdiff(self) -> "XXpr":
        return self.xpr(5, "xdiff")

    @property
    def xxdiff(self) -> "XXpr":
        return self.xpr(6, "xxdiff")


@armregistry.register_tag("MLS", ARMOpcode)
class ARMMultiplySubtract(ARMOpcode):
    """Multiplies two values and subtracts the product from a third register.

    MLS<c> <Rd>, <Rn>, <Rm>, <Ra>

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
        self.check_key(2, 4, "MultiplySubtract")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxxxxxx

        vars[0]: lhs1 (Rd)
        xprs[0]: rhs1 (Rn)
        xprs[1]: rhs2 (Rm)
        xprs[2]: rhsra (Ra)
        xprs[3]: (rhs1 * rhs2)
        xprs[4]: (rhs1 * rhs2) (simplified)
        xprs[5]: (rhsra - (rhs1 * rhs2))
        xprs[6]: (rhsra - (rhs1 * rhs2)) (simplified)
        """

        xd = ARMMultiplySubtractXData(xdata)
        if xd.is_ok:
            lhs = str(xd.vrd)
            xprod = xd.xprod
            xxprod = xd.xxprod
            rprod = simplify_result(xdata.args[4], xdata.args[5], xprod, xxprod)
            xdiff = xd.xdiff
            xxdiff = xd.xxdiff
            rdiff = simplify_result(xdata.args[6], xdata.args[7], xdiff, xxdiff)
            return (lhs + " := " + rdiff)
        else:
            return "Error value"
