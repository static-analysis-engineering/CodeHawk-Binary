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
"""Dictionary of Power-specific operand and opcode types."""

import importlib
import os

import xml.etree.ElementTree as ET

from typing import TYPE_CHECKING

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand
from chb.pwr.PowerOperandKind import PowerOperandKind

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.AppAccess import AppAccess
    from chb.app.BDictionary import BDictionary

pwrdir = os.path.dirname(os.path.abspath(__file__))
opcodes = os.path.join(pwrdir, "opcodes")
for f in os.listdir(opcodes):
    if f.startswith("PWR") and f.endswith(".py"):
        importlib.import_module("chb.pwr.opcodes." + f[:-3])


class PowerDictionary:

    def __init__(self, app: "AppAccess", xnode: ET.Element) -> None:
        self._app = app
        self.opkind_table = IT.IndexedTable("pwr-opkind-table")
        self.operand_table = IT.IndexedTable("pwr-operand-table")
        self.opcode_table = IT.IndexedTable("pwr-opcode-table")
        self.bytestring_table = SI.StringIndexedTable("pwr-bytestring-table")
        self.tables = [
            self.opkind_table,
            self.operand_table,
            self.opcode_table
        ]
        self._initialize(xnode)

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def bd(self) -> "BDictionary":
        return self.app.bdictionary

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self.app.interfacedictionary

    # ------------------------ retrieve items from tables ----------------------

    def pwr_opkind(self, ix: int) -> PowerOperandKind:
        return pwrregistry.mk_instance(
            self, self.opkind_table.retrieve(ix), PowerOperandKind)

    def pwr_operand(self, ix: int) -> PowerOperand:
        return PowerOperand(self, self.operand_table.retrieve(ix))

    def pwr_opcode(self, ix: int) -> PowerOpcode:
        try:
            return pwrregistry.mk_instance(
                self, self.opcode_table.retrieve(ix), PowerOpcode)
        except UF.CHBError as e:
            raise UF.CHBError(
                "Trying to create opcode class for "
                + str(ix)
                + ":\n"
                + str(e))

    def pwr_bytestring(self, ix: int) -> str:
            return self.bytestring_table.retrieve(ix)

    # ------------------------- xml accessors ----------------------------------

    def read_xml_pwr_opcode(self, n: ET.Element) -> PowerOpcode:
        index = n.get("iopc")
        if index is None:
            raise UF.CHBError("No index found for power opcode record")
        return self.pwr_opcode(int(index))

    def read_xml_pwr_bytestring(self, n: ET.Element) -> str:
        index = n.get("ibt")
        if index is None:
            raise UF.CHBError("Attribute ibt not found in bytestring node")
        return self.pwr_bytestring(int(index))

    # -------------------- initialize dictionary from file ---------------------

    def _initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.reset()
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError(
                    "Table " + t.name + " not found in pwrdictionary")
        xstable = xnode.find(self.bytestring_table.name)
        if xstable is not None:
            self.bytestring_table.reset()
            self.bytestring_table.read_xml(xstable)
            
            
