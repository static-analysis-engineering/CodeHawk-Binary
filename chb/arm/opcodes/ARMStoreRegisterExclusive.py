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
    import chb.arm.ARMDictionary


@armregistry.register_tag("STREX", ARMOpcode)
class ARMStoreRegisterExclusive(ARMOpcode):
    """Stores a word from a register into memory if the processor has exclusive access.

    STREX<c> <Rd>, <Rt>, [<base>, <offset>]

    tags[1]: <c>
    args[0]: index of status operand in armdictionary (Rd)
    args[1]: index of source operand in armdictionary (Rt)
    args[2]: index of base register in armdictionary
    args[3]: index of memory location in armdictionary
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "StoreRegisterExclusive")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vvxx .

        vars[0]: lhs (mem)
        vars[1]: lhs (Rd)
        xprs[0]: rhs
        xprs[1]: rhs (simplified)
        """

        lhs = str(xdata.vars[0])
        lhs2 = str(xdata.vars[1])
        rhs = str(xdata.xprs[1])
        return lhs + " := " + rhs + "; " + lhs2 + " [0;1]"
