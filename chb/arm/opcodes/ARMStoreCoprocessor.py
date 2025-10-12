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


@armregistry.register_tag("STCL", ARMOpcode)
@armregistry.register_tag("STC", ARMOpcode)
@armregistry.register_tag("STC2", ARMOpcode)
@armregistry.register_tag("STC2L", ARMOpcode)
class ARMStoreCoprocessor(ARMOpcode):
    """Stores memory data from a coprocessor to a sequence of addresses.

    STC{L}<c> <coproc>, <CRd>, [<Rn>, +/-#<imm>]

    tags[1]: <c>
    args[0]: is-long
    args[1]: is-ta2
    args[2]: coproc
    args[3]: CRd
    args[4]: index of memory address
    args[5]: optional option
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 6, "StoreCoprocessor")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[4])]

    @property
    def operandstring(self) -> str:
        coproc = "p" + str(self.args[2])
        crd = "c" + str(self.args[3])
        return (
            coproc
            + ", "
            + crd
            + ", "
            + str(self.operands[0]))

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        return "store coprocessor"
