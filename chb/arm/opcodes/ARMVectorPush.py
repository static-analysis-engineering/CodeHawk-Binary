# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023 Aarno Labs LLC
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

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMExtensionRegListOp


@armregistry.register_tag("VPUSH", ARMOpcode)
class ARMVectorPush(ARMOpcode):
    """Stores multiple consecutive extension registers to the stack.

    tags[1]: <c>
    args[0]: index of stackpointer in armdictionary
    args[1]: index of register list in armdictionary
    args[2]: index of multiple memory locations in armdictionary

    xdata format: a:vv(n)xxxx(n)x(n)dd(n)hh(n)  (SP + registers pushed)
    --------------------------------------------------------------------
    vars[0]: SP
    vars[1..n]: v(m) for m: memory location variable
    xprs[0]: SP
    xprs[1]: SP updated
    xprs[2]: SP updated, simplified
    xprs[3..n+2]: x(r) for r: register pushed
    xprs[n+3..2n+3]: xaddr for register pushed
    rdefs[0]: SP
    rdefs[1..n]: rdef(r) for r: register pushed
    uses[0]: SP
    uses[1..n]: uses(m): for m: memory location variable used
    useshigh[0]: SP
    useshigh[1..n]: useshigh(m): for m: memory location variable used at high level
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VectorPush")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[1])]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def register_count(self) -> int:
        return cast ("ARMExtensionRegListOp", self.opargs[1].opkind).count

    def annotation(self, xdata: InstrXData) -> str:
        vars = xdata.vars
        xprs = xdata.xprs
        assigns = "; ".join(
            str(v) + " := " + str(x) for (v, x) in zip(vars, xprs[2:]))
        return assigns
