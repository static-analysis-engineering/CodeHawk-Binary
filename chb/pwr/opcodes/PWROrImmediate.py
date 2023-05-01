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

@pwrregistry.register_tag("ori", PowerOpcode)
@pwrregistry.register_tag("oris", PowerOpcode)
@pwrregistry.register_tag("e_ori", PowerOpcode)
@pwrregistry.register_tag("e_ori.", PowerOpcode)
@pwrregistry.register_tag("e_or2i", PowerOpcode)
@pwrregistry.register_tag("e_or2is", PowerOpcode)
class PWROrImmediate(PowerOpcode):
    """Bitwise or immediate value to a register

    ori rA,rS,UIMM

    tags[1]: pit: instruction type
    args[0]: rc: record condition
    args[1]: s: shifted if 1
    args[2]: op2: only two operands if 1
    args[3]: ra: index of destination register in pwrdictionary
    args[4]: rs: index of source register in pwrdictionary
    args[5]: uimm: index of unsigned immediate value in pwrdictionary
    args[6]: cr: index of condition register field in pwrdictionary

    xdata format:
    -------------
    vars[0]: rA
    xprs[0]: rS
    xprs[1]: UIMM
    xprs[2]: rS + UIMM
    xprs[3]: (rS + UIMM) rewritten
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[4:]]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[4:]]

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[2])
        rrhs = str(xdata.xprs[3])
        return lhs + " := " + rhs + " (= " + rrhs + ")"
