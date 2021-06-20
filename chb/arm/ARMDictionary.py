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
"""Dictionary of ARM-specific operand and opcode types."""

import importlib
import os

import xml.etree.ElementTree as ET

from typing import TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMMemoryOffset import ARMMemoryOffset
from chb.arm.ARMOpcode import ARMOpcode
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind
from chb.arm.ARMShiftRotate import ARMShiftRotate

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI

if TYPE_CHECKING:
    import chb.app.AppAccess
    import chb.app.BDictionary

armdir = os.path.dirname(os.path.abspath(__file__))
opcodes = os.path.join(armdir, "opcodes")
for f in os.listdir(opcodes):
    if f.startswith("ARM") and f.endswith(".py"):
        importlib.import_module("chb.arm.opcodes." + f[:-3])


class ARMDictionary:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element) -> None:
        self._app = app
        self.register_shift_table = IT.IndexedTable("register-shift-table")
        self.memory_offset_table = IT.IndexedTable("arm-memory-offset-table")
        self.opkind_table = IT.IndexedTable("arm-opkind-table")
        self.operand_table = IT.IndexedTable("arm-operand-table")
        self.opcode_table = IT.IndexedTable("arm-opcode-table")
        self.bytestring_table = SI.StringIndexedTable("arm-bytestring-table")
        self.instr_class_table = IT.IndexedTable("arm-instr-class-table")
        self.tables = [
            self.register_shift_table,
            self.memory_offset_table,
            self.opkind_table,
            self.operand_table,
            self.opcode_table
        ]
        self.initialize(xnode)

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self._app

    @property
    def bd(self) -> "chb.app.BDictionary.BDictionary":
        return self.app.bdictionary

    # ------------------ retrieve items from dictionary tables -----------------

    def arm_register_shift(self, ix: int) -> ARMShiftRotate:
        return armregistry.mk_instance(
            self, self.register_shift_table.retrieve(ix), ARMShiftRotate)

    def arm_memory_offset(self, ix: int) -> ARMMemoryOffset:
        return armregistry.mk_instance(
            self, self.memory_offset_table.retrieve(ix), ARMMemoryOffset)

    def arm_opkind(self, ix: int) -> ARMOperandKind:
        return armregistry.mk_instance(
            self, self.opkind_table.retrieve(ix), ARMOperandKind)

    def arm_operand(self, ix: int) -> ARMOperand:
        return ARMOperand(self, self.operand_table.retrieve(ix))

    def arm_opcode(self, ix: int) -> ARMOpcode:
        try:
            return armregistry.mk_instance(
                self, self.opcode_table.retrieve(ix), ARMOpcode)
        except UF.CHBError as e:
            print("*" * 80)
            print("Trying to create opcode class for " + str(ix))
            print(str(e))
            print("*" * 80)
            exit(1)

    def arm_bytestring(self, ix: int) -> str:
        return self.bytestring_table.retrieve(ix)

    # -------------------------- xml accessors ---------------------------------

    def read_xml_arm_opcode(self, n: ET.Element) -> ARMOpcode:
        index = n.get("iopc")
        if index is None:
            raise UF.CHBError("No index found for arm-opcode record")
        return self.arm_opcode(int(index))

    def read_xml_arm_bytestring(self, n: ET.Element) -> str:
        id = n.get("ibt")
        if id:
            return self.arm_bytestring(int(id))
        else:
            raise UF.CHBError("Attribute ibt not found in bytestring node")

    # -------------------- initialize dictionary from file ---------------------

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.reset()
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError("Table " + t.name + " not found in armdictionary")
        xstable = xnode.find(self.bytestring_table.name)
        if xstable is not None:
            self.bytestring_table.reset()
            self.bytestring_table.read_xml(xstable)
