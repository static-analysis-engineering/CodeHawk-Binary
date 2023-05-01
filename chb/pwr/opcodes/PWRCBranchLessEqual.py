# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import cast, List, Sequence, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary

@pwrregistry.register_tag("ble", PowerOpcode)
@pwrregistry.register_tag("e_ble", PowerOpcode)
@pwrregistry.register_tag("se_ble", PowerOpcode)
class PWRCompareImmediate(PowerOpcode):
    """Conditional branch if less-equal

    tags[1]: pit: instruction type
    args[0]: aa: absolute address if 1
    args[1]: bo: BO value (0..31)
    args[2]: bi: BI value (0..31)
    args[3]: bp: index of branch prediction in pwrdictionary
    args[4]: cr: index of condition register field in pwrdictionary
    args[5]: bd: index of branch destination address in pwrdictionary

    xdata format:
    -------------
    xprs[0]: true condition
    xprs[1]: false condition
    xprs[2]: true condition (simplified)
    xprs[3]: false condition (simplified)
    xprs[4]: target address (absolute)
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[4:]]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[3:]]

    def annotation(self, xdata: InstrXData) -> str:
        if xdata.has_branch_conditions():
            return "if " + str(xdata.xprs[2]) + " then goto " + str(xdata.xprs[4])
        else:
            return "?"
