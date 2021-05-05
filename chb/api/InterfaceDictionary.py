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

import chb.api.CallTarget as CT
import chb.api.FunctionStub as FS
import chb.api.InterfaceDictionaryRecord as D
import chb.util.IndexedTable as IT
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.AppAccess
    import chb.app.BDictionary


class InterfaceDictionary:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element) -> None:
        self._app = app
        self.function_stub_table: IT.IndexedTable[FS.FunctionStub] = IT.IndexedTable('function-stub-table')
        self.call_target_table: IT.IndexedTable[CT.CallTarget] = IT.IndexedTable('call-target-table')
        self.tables: List[Tuple[IT.IndexedTableSuperclass, Callable[[ET.Element], None]]] = [
            (self.function_stub_table, self._read_xml_function_stub_table),
            (self.call_target_table, self._read_xml_call_target_table)
            ]
        self.initialize(xnode)

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self._app

    @property
    def bdictionary(self) -> "chb.app.BDictionary.BDictionary":
        return self.app.bdictionary

    # -------------- Retrieve items from dictionary tables ---------------------

    def get_function_stub(self, ix: int) -> FS.FunctionStub:
        return self.function_stub_table.retrieve(ix)

    def get_call_target(self, ix: int) -> CT.CallTarget:
        return self.call_target_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_call_target(self, n: ET.Element) -> CT.CallTarget:
        index = n.get("ictgt")
        if index is not None:
            return self.get_call_target(int(index))
        else:
            raise UF.CHBError("Index ictgt not found in call target node")

    # ---------------- Initialize dictionary from file -------------------------

    def initialize(self, xnode: ET.Element) -> None:
        for (t, f) in self.tables:
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.reset()
                f(xtable)
            else:
                raise UF.CHBError("Table "
                                  + t.name
                                  + " not found in interface dictionary")

    def _read_xml_function_stub_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element) -> FS.FunctionStub:
            rep = IT.get_rep(node)
            args = (self,) + rep
            return D.apiregistry.construct_instance(*args, FS.FunctionStub)
        self.function_stub_table.read_xml(txnode, "n", get_value)

    def _read_xml_call_target_table(self, txnode: ET.Element) -> None:
        def get_value(node: ET.Element) -> CT.CallTarget:
            rep = IT.get_rep(node)
            args = (self,) + rep
            return D.apiregistry.construct_instance(*args, CT.CallTarget)
        self.call_target_table.read_xml(txnode, "n", get_value)
