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
"""Dictionary for indexing basic data structures."""

import xml.etree.ElementTree as ET

import chb.app.DictionaryRecord as D
import chb.arm.ARMRegister as ARM
import chb.asm.AsmRegister as AR
import chb.mips.MIPSRegister as MR
import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI

from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.app.AppAccess

class AsmAddress:

    def __init__(self, index: int, tags: List[str], args: List[int]):
        self.index = index
        self.tags = tags
        self.args = args

    def get_key(self) -> Tuple[str, str]:
        return (','.join(self.tags), ','.join([str(x) for x in self.args]))

    def get_hex(self) -> str:
        return(self.tags[0])

    def get_int(self) -> int:
        return int(self.tags[0], 16)

    def __str__(self) -> str:
        return self.get_hex()


register_constructors = {
    'a': lambda x: ARM.ARMRegister(*x),
    's': lambda x: AR.SegmentRegister(*x),
    'c': lambda x: AR.CPURegister(*x),
    'd': lambda x: AR.DoubleRegister(*x),
    'f': lambda x: AR.FloatingPointRegister(*x),
    'ctr': lambda x: AR.ControlRegister(*x),
    'dbg': lambda x: AR.DebugRegister(*x),
    'm': lambda x: AR.MmxRegister(*x),
    'x': lambda x: AR.XmmRegister(*x),
    'p': lambda x: MR.MIPSRegister(*x),
    'ps': lambda x: MR.MIPSSpecialRegister(*x),
    'pfp': lambda x: MR.MIPSFloatingPointRegister(*x)
    }


class BDictionary:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element):
        self.app = app
        self.string_table = SI.StringIndexedTable('string-table')
        self.address_table = IT.IndexedTable('address-table')
        self.register_table = IT.IndexedTable('register-table')
        self.tables = [
            (self.address_table, self._read_xml_address_table),
            (self.register_table, self._read_xml_register_table)
            ]
        self.string_tables = [
            (self.string_table, self._read_xml_string_table)
            ]
        self.initialize(xnode)

    # -------------- Retrieve items from dictionary tables ---------------------

    def get_string(self, ix: int) -> str:
        return self.string_table.retrieve(ix)

    def get_address(self, ix: int) -> AsmAddress:
        return self.address_table.retrieve(ix)

    def get_register(self, ix: int) -> D.BDictionaryRecord:
        return self.register_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_string(self, n: ET.Element) -> str:
        index = n.get("istr")
        if index:
            return self.get_string(int(index))
        raise UF.CHBError("Error in reading from string table: tag missing")

    # ---------------- Initialize dictionary from file -------------------------

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

    def _read_xml_string_table(self, txnode: ET.Element) -> None:
        self.string_table.read_xml(txnode)

    def _read_xml_address_table(self, txnode: ET.Element) -> None:
        def get_value(node):
            rep = IT.get_rep(node)
            args = rep
            return AsmAddress(*args)
        self.address_table.read_xml(txnode, 'n', get_value)

    def _read_xml_register_table(self, txnode: ET.Element) -> None:
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return register_constructors[tag](args)
        self.register_table.read_xml(txnode, 'n', get_value)
