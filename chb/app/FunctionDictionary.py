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
"""Function-level dictionary that holds instruction expressions."""

import xml.etree.ElementTree as ET

import chb.app.InstrXData as I
import chb.app.StackPointerOffset as S
import chb.util.IndexedTable as IT
import chb.util.fileutil as UF

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import chb.app.Function


class FunctionDictionary:

    def __init__(
            self,
            fn: "chb.app.Function.Function",
            xnode: ET.Element) -> None:
        self._fn = fn
        self.xnode = xnode
        self.sp_offset_table = IT.IndexedTable("sp-offset-table")
        self.instrx_table = IT.IndexedTable("instrx-table")
        self.tables = [
            (self.sp_offset_table, self._read_xml_sp_offset_table),
            (self.instrx_table, self._read_xml_instrx_table)
            ]
        self.initialize(xnode)

    @property
    def function(self) -> "chb.app.Function.Function":
        return self._fn

    # ------------------  retrieve items from dictionary tables ----------------

    def get_sp_offset(self, ix: int) -> S.StackPointerOffset:
        return self.sp_offset_table.retrieve(ix)

    def get_instrx(self, ix: int) -> I.InstrXData:
        return self.instrx_table.retrieve(ix)

    # ------------------------ xml accessors -----------------------------------

    def read_xml_sp_offset(self, n: ET.Element) -> S.StackPointerOffset:
        index = n.get("isp")
        if index is None:
            raise UF.CHBError("Index attribute missing from function dictionary")
        return self.get_sp_offset(int(index))

    def read_xml_instrx(self, n: ET.Element) -> I.InstrXData:
        index = n.get("iopx")
        if index is None:
            raise UF.CHBError("Index attribute missing from function dictionary")
        return self.get_instrx(int(index))

    # -------------------- initialize dictionary from file ---------------------

    def initialize(self, xnode: ET.Element) -> None:
        if xnode is None:
            return
        for (t, f) in self.tables:
            t.reset()
            table = xnode.find(t.name)
            if table is None:
                raise UF.CHBError("Indexed table " + t.name + " not found")
            f(table)

    def _read_xml_sp_offset_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element) -> S.StackPointerOffset:
            rep = IT.get_rep(node)
            args = (self,) + rep
            return S.StackPointerOffset(*args)
        self.sp_offset_table.read_xml(txnode, 'n', get_value)

    def _read_xml_instrx_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element) -> I.InstrXData:
            rep = IT.get_rep(node)
            args = (self,) + rep
            return I.InstrXData(*args)
        self.instrx_table.read_xml(txnode, 'n', get_value)
