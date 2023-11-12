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

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary

    
@pwrregistry.register_tag("ILLEGAL", PowerOpcode)
@pwrregistry.register_tag("add", PowerOpcode)
@pwrregistry.register_tag("add.", PowerOpcode)
@pwrregistry.register_tag("addc", PowerOpcode)
@pwrregistry.register_tag("addic", PowerOpcode)
@pwrregistry.register_tag("addic.", PowerOpcode)
@pwrregistry.register_tag("addze", PowerOpcode)
@pwrregistry.register_tag("addze.", PowerOpcode)
@pwrregistry.register_tag("and", PowerOpcode)
@pwrregistry.register_tag("and.", PowerOpcode)
@pwrregistry.register_tag("andc", PowerOpcode)
@pwrregistry.register_tag("andc.", PowerOpcode)
@pwrregistry.register_tag("andi.", PowerOpcode)
@pwrregistry.register_tag("andis.", PowerOpcode)
@pwrregistry.register_tag("bctr", PowerOpcode)
@pwrregistry.register_tag("bdnz", PowerOpcode)
@pwrregistry.register_tag("bdz", PowerOpcode)
@pwrregistry.register_tag("beq-", PowerOpcode)
@pwrregistry.register_tag("beq+", PowerOpcode)
@pwrregistry.register_tag("beqlr", PowerOpcode)
@pwrregistry.register_tag("beqlr+", PowerOpcode)
@pwrregistry.register_tag("bge", PowerOpcode)
@pwrregistry.register_tag("bge+", PowerOpcode)
@pwrregistry.register_tag("bge-", PowerOpcode)
@pwrregistry.register_tag("bgtlr+", PowerOpcode)
@pwrregistry.register_tag("ble+", PowerOpcode)
@pwrregistry.register_tag("ble-", PowerOpcode)
@pwrregistry.register_tag("blt-", PowerOpcode)
@pwrregistry.register_tag("bne", PowerOpcode)
@pwrregistry.register_tag("bne+", PowerOpcode)
@pwrregistry.register_tag("bne-", PowerOpcode)
@pwrregistry.register_tag("bnelr+", PowerOpcode)
@pwrregistry.register_tag("clrlslwi", PowerOpcode)
@pwrregistry.register_tag("clrrwi", PowerOpcode)
@pwrregistry.register_tag("clrrwi.", PowerOpcode)
@pwrregistry.register_tag("cntlzw", PowerOpcode)
@pwrregistry.register_tag("crclr", PowerOpcode)
@pwrregistry.register_tag("divw", PowerOpcode)
@pwrregistry.register_tag("evldd", PowerOpcode)
@pwrregistry.register_tag("evstdd", PowerOpcode)
@pwrregistry.register_tag("evxor", PowerOpcode)
@pwrregistry.register_tag("extrwi.", PowerOpcode)
@pwrregistry.register_tag("extsb", PowerOpcode)
@pwrregistry.register_tag("insrwi", PowerOpcode)
@pwrregistry.register_tag("isel", PowerOpcode)
@pwrregistry.register_tag("iseleq", PowerOpcode)
@pwrregistry.register_tag("isellt", PowerOpcode)
@pwrregistry.register_tag("lbzx", PowerOpcode)
@pwrregistry.register_tag("lha", PowerOpcode)
@pwrregistry.register_tag("lhau", PowerOpcode)
@pwrregistry.register_tag("lhax", PowerOpcode)
@pwrregistry.register_tag("lhzuu", PowerOpcode)
@pwrregistry.register_tag("lhzx", PowerOpcode)
@pwrregistry.register_tag("lmw", PowerOpcode)
@pwrregistry.register_tag("lwzux", PowerOpcode)
@pwrregistry.register_tag("lwzx", PowerOpcode)
@pwrregistry.register_tag("mfctr", PowerOpcode)
@pwrregistry.register_tag("mr", PowerOpcode)
@pwrregistry.register_tag("mr.", PowerOpcode)
@pwrregistry.register_tag("mfcr", PowerOpcode)
@pwrregistry.register_tag("mtcrf", PowerOpcode)
@pwrregistry.register_tag("mulhw", PowerOpcode)
@pwrregistry.register_tag("mulhwu", PowerOpcode)
@pwrregistry.register_tag("mulli", PowerOpcode)
@pwrregistry.register_tag("neg", PowerOpcode)
@pwrregistry.register_tag("not", PowerOpcode)
@pwrregistry.register_tag("orc", PowerOpcode)
@pwrregistry.register_tag("rlwimi", PowerOpcode)
@pwrregistry.register_tag("rotlw", PowerOpcode)
@pwrregistry.register_tag("slw", PowerOpcode)
@pwrregistry.register_tag("xor", PowerOpcode)
@pwrregistry.register_tag("xori", PowerOpcode)
@pwrregistry.register_tag("sraw", PowerOpcode)
@pwrregistry.register_tag("srawi", PowerOpcode)
@pwrregistry.register_tag("srw", PowerOpcode)
@pwrregistry.register_tag("stbx", PowerOpcode)
@pwrregistry.register_tag("sthu", PowerOpcode)
@pwrregistry.register_tag("sthx", PowerOpcode)
@pwrregistry.register_tag("stmw", PowerOpcode)
@pwrregistry.register_tag("stwx", PowerOpcode)
@pwrregistry.register_tag("subfc", PowerOpcode)
@pwrregistry.register_tag("subfe", PowerOpcode)
@pwrregistry.register_tag("subfic", PowerOpcode)
@pwrregistry.register_tag("subfze", PowerOpcode)
@pwrregistry.register_tag("xori", PowerOpcode)
@pwrregistry.register_tag("xoris", PowerOpcode)
@pwrregistry.register_tag("xr", PowerOpcode)

class PWRNOP(PowerOpcode):

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        # return [self.pwrd.pwr_operand(i) for i in self.args[2:]]
        return []

    def annotation(self, xdata: InstrXData) -> str:
        return "not expanded yet"
    
