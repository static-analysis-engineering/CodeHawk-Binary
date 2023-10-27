# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
"""Variable dictionary local to a particular function."""

import xml.etree.ElementTree as ET

from typing import Callable, List, Optional, Tuple, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import varregistry
from chb.invariants.FnXprDictionary import FnXprDictionary
from chb.invariants.VAssemblyVariable import VAssemblyVariable
from chb.invariants.VConstantValueVariable import VConstantValueVariable
from chb.invariants.VMemoryBase import VMemoryBase
from chb.invariants.VMemoryOffset import VMemoryOffset

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.BDictionary import BDictionary
    from chb.app.Function import Function
    from chb.app.FunctionInfo import FunctionInfo
    from chb.app.StringXRefs import StringsXRefs
    from chb.bctypes.BCDictionary import BCDictionary


class FnVarDictionary:

    def __init__(
            self,
            function: "Function",
            xnode: ET.Element) -> None:
        self._function = function
        self.xnode = xnode
        self._xd: Optional[FnXprDictionary] = None
        self.memory_base_table = IT.IndexedTable('memory-base-table')
        self.memory_offset_table = IT.IndexedTable('memory-offset-table')
        self.assembly_variable_denotation_table = IT.IndexedTable(
            'assembly-variable-denotation-table')
        self.constant_value_variable_table = IT.IndexedTable(
            'constant-value-variable-table')
        self.tables: List[IT.IndexedTable] = [
            self.memory_base_table,
            self.memory_offset_table,
            self.assembly_variable_denotation_table,
            self.constant_value_variable_table
        ]
        self.initialize(xnode)

    @property
    def function(self) -> "Function":
        return self._function

    @property
    def finfo(self) -> "FunctionInfo":
        return self.function.finfo

    @property
    def faddr(self) -> str:
        return self.function.faddr

    @property
    def bd(self) -> "BDictionary":
        return self.function.bd

    @property
    def bcd(self) -> "BCDictionary":
        return self.function.bcd

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self.function.ixd

    @property
    def stringsxrefs(self) -> "StringsXRefs":
        return self.function.stringsxrefs

    @property
    def xd(self) -> FnXprDictionary:
        if self._xd is None:
            xprd = self.xnode.find("xpr-dictionary")
            if xprd is not None:
                self._xd = FnXprDictionary(self, xprd)
            else:
                raise UF.CHBError(
                    "Xpr-dictionary not found in variable dictionary "
                    "for function " + self.faddr)
        return self._xd

    # ------------------------------------------- Retrieve dictionary tables ---

    def constant_value_variables(self) -> List[VConstantValueVariable]:
        return [self.constant_value_variable(i)
                for i in self.constant_value_variable_table.keys()]

    # -------------------------------- Retrieve Items from dictionary tables ---

    def memory_base(self, ix: int) -> VMemoryBase:
        if ix > 0:
            return varregistry.mk_instance(
                self, self.memory_base_table.retrieve(ix), VMemoryBase)
        else:
            raise UF.CHBError("Illegal memory base index value: " + str(ix))

    def memory_offset(self, ix: int) -> VMemoryOffset:
        if ix > 0:
            return varregistry.mk_instance(
                self, self.memory_offset_table.retrieve(ix), VMemoryOffset)
        else:
            raise UF.CHBError("Illegal memory offset index value: " + str(ix))

    def assembly_variable_denotation(self, ix: int) -> VAssemblyVariable:
        if ix > 0:
            return varregistry.mk_instance(
                self,
                self.assembly_variable_denotation_table.retrieve(ix),
                VAssemblyVariable)
        else:
            raise UF.CHBError("Illegal assembly variable index value: "
                              + str(ix))

    def constant_value_variable(self, ix: int) -> VConstantValueVariable:
        if ix > 0:
            return varregistry.mk_instance(
                self,
                self.constant_value_variable_table.retrieve(ix),
                VConstantValueVariable)
        else:
            raise UF.CHBError("Illegal constant-value variable index value: "
                              + str(ix))

    # -------------------------------------- Initialize dictionary from file ---

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.reset()
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError("Var dictionary table " + t.name + " not found")
