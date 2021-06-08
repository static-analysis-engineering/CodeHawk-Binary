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
"""Dictionary of X86-specific operand and opcode types."""

import importlib
import os

import xml.etree.ElementTree as ET

from typing import Callable, List, Tuple, TYPE_CHECKING

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand
from chb.x86.X86OperandKind import X86OperandKind


if TYPE_CHECKING:
    import chb.api.InterfaceDictionary
    import chb.app.BDictionary
    import chb.x86.X86Access

x86dir = os.path.dirname(os.path.abspath(__file__))
opcodes = os.path.join(x86dir, "opcodes")
for f in os.listdir(opcodes):
    if f.startswith("X86") and f.endswith(".py"):
        importlib.import_module("chb.x86.opcodes." + f[:-3])


class X86Dictionary:

    def __init__(self,
                 app: "chb.x86.X86Access.X86Access",
                 xnode: ET.Element) -> None:
        self._app = app
        self.opkind_table = IT.IndexedTable('opkind-table')
        self.operand_table = IT.IndexedTable('operand-table')
        self.opcode_table = IT.IndexedTable('opcode-table')
        self.bytestring_table = SI.StringIndexedTable('bytestring-table')
        self.opcode_text_table = SI.StringIndexedTable('opcode-text-table')
        self.tables: List[IT.IndexedTable] = [
            self.opkind_table,
            self.operand_table,
            self.opcode_table
        ]
        self.string_tables = [
            self.bytestring_table,
            self.opcode_text_table
        ]
        self.initialize(xnode)

    @property
    def app(self) -> "chb.x86.X86Access.X86Access":
        return self._app

    @property
    def bd(self) -> "chb.app.BDictionary.BDictionary":
        return self.app.bdictionary

    @property
    def ixd(self) -> "chb.api.InterfaceDictionary.InterfaceDictionary":
        return self.app.interfacedictionary

    def get_instr_bytes(self) -> List[str]:
        return self.bytestring_table.values()

    # ------------------- retrieve items from dictionary tables ----------------

    def opkind(self, ix: int) -> X86OperandKind:
        return x86registry.mk_instance(
            self, self.opkind_table.retrieve(ix), X86OperandKind)

    def operand(self, ix: int) -> X86Operand:
        return X86Operand(self, self.operand_table.retrieve(ix))

    def opcode(self, ix: int) -> X86Opcode:
        return x86registry.mk_instance(
            self, self.opcode_table.retrieve(ix), X86Opcode)

    def bytestring(self, ix: int) -> str:
        return self.bytestring_table.retrieve(ix)

    def opcode_text(self, ix: int) -> str:
        return self.opcode_text_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_opcode_text(self, n: ET.Element) -> str:
        id = n.get("itxt")
        if id:
            return self.opcode_text(int(id))
        else:
            raise UF.CHBError("Attribute itxt not found in opcode-text node")

    def read_xml_opcode(self, n: ET.Element) -> X86Opcode:
        id = n.get("iopc")
        if id:
            return self.opcode(int(id))
        else:
            raise UF.CHBError("Attribute iopc not found in opcode node")

    def read_xml_bytestring(self, n: ET.Element) -> str:
        id = n.get("ibt")
        if id:
            return self.bytestring(int(id))
        else:
            raise UF.CHBError("Attribute ibt not found in bytestring node")

    # ----------------------- initialize dictionary from file ------------------

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            t.reset()
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError("Table "
                                  + t.name
                                  + " is missing from x86dictionary")
        for ts in self.string_tables:
            ts.reset()
            xstable = xnode.find(ts.name)
            if xstable is not None:
                ts.read_xml(xstable)
            else:
                raise UF.CHBError("Table "
                                  + ts.name
                                  + " is missing from x86dictionary")
