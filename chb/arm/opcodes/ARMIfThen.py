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


@armregistry.register_tag("ITE CS", ARMOpcode)
@armregistry.register_tag("ITTE GT", ARMOpcode)
@armregistry.register_tag("ITTE GE", ARMOpcode)
@armregistry.register_tag("ITETE LE", ARMOpcode)
@armregistry.register_tag("IT LT", ARMOpcode)
@armregistry.register_tag("ITE CC", ARMOpcode)
@armregistry.register_tag("ITT GT", ARMOpcode)
@armregistry.register_tag("ITET HI", ARMOpcode)
@armregistry.register_tag("ITT LT", ARMOpcode)
@armregistry.register_tag("ITTTT HI", ARMOpcode)
@armregistry.register_tag("ITTT HI", ARMOpcode)
@armregistry.register_tag("IT GE", ARMOpcode)
@armregistry.register_tag("IT GT", ARMOpcode)
@armregistry.register_tag("ITTTT GT", ARMOpcode)
@armregistry.register_tag("ITTTE GT", ARMOpcode)
@armregistry.register_tag("ITE GE", ARMOpcode)
@armregistry.register_tag("ITT GE", ARMOpcode)
@armregistry.register_tag("ITTTT CS", ARMOpcode)
@armregistry.register_tag("ITT NE", ARMOpcode)
@armregistry.register_tag("ITE EQ", ARMOpcode)
@armregistry.register_tag("ITE LT", ARMOpcode)
@armregistry.register_tag("ITE NE", ARMOpcode)
@armregistry.register_tag("IT CC", ARMOpcode)
@armregistry.register_tag("IT CS", ARMOpcode)
@armregistry.register_tag("IT EQ", ARMOpcode)
@armregistry.register_tag("IT HI", ARMOpcode)
@armregistry.register_tag("IT LS", ARMOpcode)
@armregistry.register_tag("ITT EQ", ARMOpcode)
@armregistry.register_tag("ITET EQ", ARMOpcode)
@armregistry.register_tag("ITTT EQ", ARMOpcode)
@armregistry.register_tag("ITE LS", ARMOpcode)
@armregistry.register_tag("ITET LS", ARMOpcode)
@armregistry.register_tag("ITETE EQ", ARMOpcode)
@armregistry.register_tag("ITTEE EQ", ARMOpcode)
@armregistry.register_tag("ITETT EQ", ARMOpcode)
@armregistry.register_tag("ITTT LT", ARMOpcode)
@armregistry.register_tag("IT NE", ARMOpcode)
@armregistry.register_tag("IT PL", ARMOpcode)
@armregistry.register_tag("ITTET EQ", ARMOpcode)
@armregistry.register_tag("ITTT CC", ARMOpcode)
class ARMIfThen(ARMOpcode):
    """Makes up to four following instructions conditional.

    The conditions for the instructions in the IT block are the same as, or the
    inverse of, the condition of the TI instruction specifies for the first
    instruction in the block..

    IT{<x>{<y>{<z>}}} <firstcond>

    tags[1]: <c>
    tags[2]: xyz
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return []

    def annotation(self, xdata: InstrXData) -> str:
        return self.tags[0]
