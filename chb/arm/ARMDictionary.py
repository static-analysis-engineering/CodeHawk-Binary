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
"""Dictionary of ARM-specific operand types."""

import xml.etree.ElementTree as ET

from typing import TYPE_CHECKING

import chb.app.DictionaryRecord as D

import chb.arm.ARMMemoryOffset as M
import chb.arm.ARMOpcode as AOP
import chb.arm.ARMOpcodeBase as B
import chb.arm.ARMOperand as OP
import chb.arm.ARMOperandKind as K
import chb.arm.ARMShiftRotate as R

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI

if TYPE_CHECKING:
    import chb.app.AppAccess

arm_opkind_constructors = {
    "a": lambda x: K.ARMAbsoluteOp(*x),
    "b": lambda x: K.ARMRegBitSequenceOp(*x),
    "i": lambda x: K.ARMImmediateOp(*x),
    "l": lambda x: K.ARMRegListOp(*x),
    "m": lambda x: K.ARMMemMultipleOp(*x),
    "o": lambda x: K.ARMOffsetAddressOp(*x),
    "r": lambda x: K.ARMRegisterOp(*x),
    "s": lambda x: K.ARMShiftedRegisterOp(*x)
    }

arm_srt_constructors = {
    "i": lambda x: R.ARMImmSRT(*x),
    "r": lambda x: R.ARMRegSRT(*x)
    }

arm_memory_offset_constructors = {
    "i": lambda x: M.ARMImmOffset(*x),
    "x": lambda x: M.ARMIndexOffset(*x),
    "s": lambda x: M.ARMShiftedIndexOffset(*x)
    }


class ARMDictionary:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element) -> None:
        self.app = app
        self.register_shift_table = IT.IndexedTable("register-shift-table")
        self.memory_offset_table = IT.IndexedTable("arm-memory-offset-table")
        self.opkind_table = IT.IndexedTable("arm-opkind-table")
        self.operand_table = IT.IndexedTable("arm-operand-table")
        self.opcode_table = IT.IndexedTable("arm-opcode-table")
        self.bytestring_table = SI.StringIndexedTable("arm-bytestring-table")
        self.instr_class_table = IT.IndexedTable("arm-instr-class-table")
        self.tables = [
            (self.register_shift_table, self._read_xml_arm_register_shift_table),
            (self.memory_offset_table, self._read_xml_arm_memory_offset_table),
            (self.opkind_table, self._read_xml_arm_opkind_table),
            (self.operand_table, self._read_xml_arm_operand_table),
            (self.opcode_table, self._read_xml_arm_opcode_table)
        ]
        self.string_tables = [
            (self.bytestring_table, self._read_xml_arm_bytestring_table)
            ]
        self.initialize(xnode)

    # ------------------ retrieve items from dictionary tables -----------------

    def get_arm_register_shift(self, ix: int) -> R.ARMShiftRotate:
        return self.register_shift_table.retrieve(ix)

    def get_arm_memory_offset(self, ix: int) -> M.ARMMemoryOffset:
        return self.memory_offset_table.retrieve(ix)

    def get_arm_opkind(self, ix: int) -> K.ARMOperandKind:
        return self.opkind_table.retrieve(ix)

    def get_arm_operand(self, ix: int) -> OP.ARMOperand:
        return self.operand_table.retrieve(ix)

    def get_arm_opcode(self, ix: int) -> B.ARMOpcodeBase:
        return self.opcode_table.retrieve(ix)

    # -------------------------- xml accessors ---------------------------------

    def read_xml_arm_opcode(self, n: ET.Element):
        index = n.get("iopc")
        if index is None:
            raise UF.CHBError("No index found for arm-opcode record")
        return self.get_arm_opcode(int(index))

    # -------------------- initialize dictionary from file ---------------------

    def initialize(self, xnode: ET.Element) -> None:
        if xnode is None:
            return
        for (t, f) in self.tables:
            t.reset()
            tablename = xnode.find(t.name)
            if tablename:
                f(tablename)
        for (ts, fs) in self.string_tables:
            ts.reset()
            tablename = xnode.find(ts.name)
            if tablename:
                fs(tablename)

    def _read_xml_arm_register_shift_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return arm_srt_constructors[tag](args)
        self.register_shift_table.read_xml(txnode, "n", get_value)

    def _read_xml_arm_memory_offset_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return arm_memory_offset_constructors[tag](args)
        self.memory_offset_table.read_xml(txnode, "n", get_value)

    def _read_xml_arm_opkind_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return arm_opkind_constructors[tag](args)
        self.opkind_table.read_xml(txnode, "n", get_value)

    def _read_xml_arm_operand_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element) -> OP.ARMOperand:
            rep = IT.get_rep(node)
            args = (self,) + rep
            return OP.ARMOperand(*args)
        self.operand_table.read_xml(txnode, "n", get_value)

    def _read_xml_arm_opcode_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return AOP.get_arm_opcode(tag, args)
        self.opcode_table.read_xml(txnode, "n", get_value)

    def _read_xml_arm_bytestring_table(self, txnode: ET.Element) -> None:
        self.bytestring_table.read_xml(txnode)
