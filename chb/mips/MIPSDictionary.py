# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

import xml.etree.ElementTree as ET

from typing import Callable, List, Tuple, TYPE_CHECKING

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode
from chb.mips.MIPSOperand import MIPSOperand
from chb.mips.MIPSOperandKind import MIPSOperandKind

import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.BDictionary import BDictionary
    from chb.mips.MIPSAccess import MIPSAccess


class MIPSDictionary:

    def __init__(
            self,
            app: "MIPSAccess",
            xnode: ET.Element) -> None:
        self._app = app
        self.opkind_table = IT.IndexedTable('mips-opkind-table')
        self.operand_table = IT.IndexedTable('mips-operand-table')
        self.opcode_table = IT.IndexedTable('mips-opcode-table')
        self.bytestring_table = SI.StringIndexedTable('mips-bytestring-table')
        self.tables: List[IT.IndexedTable] = [
            self.opkind_table,
            self.operand_table,
            self.opcode_table
        ]
        self.initialize(xnode)

    @property
    def app(self) -> "MIPSAccess":
        return self._app

    @property
    def bd(self) -> "BDictionary":
        return self.app.bdictionary

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self.app.interfacedictionary

    # ------------------- retrieve items from dictionary tables ----------------

    def mips_opkind(self, ix: int) -> MIPSOperandKind:
        if ix > 0:
            return mipsregistry.mk_instance(
                self, self.opkind_table.retrieve(ix), MIPSOperandKind)
        else:
            raise UF.CHBError("Illegal index value for operand kind")

    def mips_operand(self, ix: int) -> MIPSOperand:
        if ix > 0:
            return MIPSOperand(self, self.operand_table.retrieve(ix))
        else:
            raise UF.CHBError("Illegal index value for operand")

    def mips_opcode(self, ix: int) -> MIPSOpcode:
        if ix > 0:
            return mipsregistry.mk_instance(
                self, self.opcode_table.retrieve(ix), MIPSOpcode)
        else:
            raise UF.CHBError("Illegal index value for mips opcode")

    def mips_bytestring(self, ix: int) -> str:
        return self.bytestring_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_mips_opcode(self, n: ET.Element) -> MIPSOpcode:
        index = n.get("iopc")
        if index is not None:
            return self.mips_opcode(int(index))
        else:
            raise UF.CHBError("Index value iopc not found")

    def read_xml_mips_bytestring(self, n: ET.Element) -> str:
        index = n.get("ibt")
        if index is not None:
            return self.mips_bytestring(int(index))
        else:
            raise UF.CHBError("Index value ibt not found")

    # ----------------------- initialize dictionary from file ------------------

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            t.reset()
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError("MIPS dictionary table "
                                  + t.name
                                  + " not found")
        self.bytestring_table.reset()
        xstable = xnode.find(self.bytestring_table.name)
        if xstable is not None:
            self.bytestring_table.read_xml(xstable)
        else:
            raise UF.CHBError("MIPS bytestring not found")
