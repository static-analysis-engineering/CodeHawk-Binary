# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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
"""Expression dictionary local to a particular function."""

import xml.etree.ElementTree as ET

from typing import Callable, List, Optional, Tuple, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import xprregistry
from chb.invariants.XBound import XBound
from chb.invariants.XConstant import XConstant
from chb.invariants.XInterval import XInterval
from chb.invariants.XNumerical import XNumerical
from chb.invariants.XprList import XprList
from chb.invariants.XSymbol import XSymbol
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr
from chb.invariants.XprList import XprList, XprListList

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.app.FunctionInfo import FunctionInfo
    from chb.invariants.FnVarDictionary import FnVarDictionary


class FnXprDictionary:
    """Indexed analysis expressions."""

    def __init__(
            self,
            vd: "FnVarDictionary",
            xnode: ET.Element) -> None:
        self._vd = vd
        self.numerical_table = IT.IndexedTable('numerical-table')
        self.bound_table = IT.IndexedTable('bound-table')
        self.interval_table = IT.IndexedTable('interval-table')
        self.symbol_table = IT.IndexedTable('symbol-table')
        self.variable_table = IT.IndexedTable('variable-table')
        self.xcst_table = IT.IndexedTable('xcst-table')
        self.xpr_table = IT.IndexedTable('xpr-table')
        self.xpr_list_table = IT.IndexedTable('xpr-list-table')
        self.xpr_list_list_table = IT.IndexedTable('xpr-list-list-table')
        self.tables: List[IT.IndexedTable] = [
            self.numerical_table,
            self.bound_table,
            self.interval_table,
            self.symbol_table,
            self.variable_table,
            self.xcst_table,
            self.xpr_table,
            self.xpr_list_table,
            self.xpr_list_list_table
        ]
        self.initialize(xnode)

    @property
    def vd(self) -> "FnVarDictionary":
        return self._vd

    @property
    def finfo(self) -> "FunctionInfo":
        return self.vd.finfo

    # ------------- Retrieve items from dictionary tables ----------------------

    def numerical(self, ix: int) -> XNumerical:
        if ix > 0:
            return XNumerical(self, self.numerical_table.retrieve(ix))
        else:
            raise UF.CHBError("Illegal index value for numerical: " + str(ix))

    def bound(self, ix: int) -> XBound:
        if ix > 0:
            return xprregistry.mk_instance(
                self, self.bound_table.retrieve(ix), XBound)
        else:
            raise UF.CHBError("Illegal index value for bound: " + str(ix))

    def interval(self, ix: int) -> XInterval:
        if ix > 0:
            return XInterval(
                self, self.interval_table.retrieve(ix))
        else:
            raise UF.CHBError("Illegal index value for interval: " + str(ix))

    def symbol(self, ix: int) -> XSymbol:
        if ix > 0:
            return XSymbol(self, self.symbol_table.retrieve(ix))
        else:
            raise UF.CHBError("Illegal index value for symbol: " + str(ix))

    def variable(self, ix: int) -> XVariable:
        if ix > 0:
            return XVariable(self, self.variable_table.retrieve(ix))
        else:
            raise UF.CHBError("Illegal index value for variable: " + str(ix))

    def xcst(self, ix: int) -> XConstant:
        if ix > 0:
            return xprregistry.mk_instance(
                self, self.xcst_table.retrieve(ix), XConstant)
        else:
            raise UF.CHBError("Illegal index value for constant: " + str(ix))

    def xpr(self, ix: int) -> XXpr:
        if ix > 0:
            return xprregistry.mk_instance(
                self, self.xpr_table.retrieve(ix), XXpr)
        else:
            raise UF.CHBError("Illegal index value for expression: " + str(ix))

    def xpr_list(self, ix: int) -> XprList:
        if ix > 0:
            return xprregistry.mk_instance(
                self, self.xpr_list_table.retrieve(ix), XprList)
        else:
            raise UF.CHBError("Illegal index value for expression list: "
                              + str(ix))

    def xpr_list_list(self, ix: int) -> XprListList:
        if ix > 0:
            return xprregistry.mk_instance(
                self, self.xpr_list_list_table.retrieve(ix), XprListList)
        else:
            raise UF.CHBError("Illegal index value for expression list list: "
                              + str(ix))

    # ------------ Provide read_xml service ------------------------------------

    # TBD

    # ------------- Index items by category ------------------------------------

    # TBD

    # -------------- Initialize dictionary from file ---------------------------

    def initialize(self, xnode: ET.Element, force: bool = False) -> None:
        for t in self.tables:
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.reset()
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError("Xpr dictionary table " + t.name + " not found")

    # ------------------ Printing ----------------------------------------------

    def xpr_table_to_string(self) -> str:
        lines: List[str] = []

        def f(ix: int, v: IT.IndexedTableValue) -> None:
            lines.append(str(ix) + ": " + str(self.xpr(ix)))

        self.xpr_table.iter(f)
        return "\n".join(lines)

    def var_table_to_string(self) -> str:
        lines: List[str] = []

        def f(ix: int, v: IT.IndexedTableValue) -> None:
            lines.append(str(ix) + ": " + str(self.variable(ix)))

        self.variable_table.iter(f)
        return "\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Variable table")
        lines.append("--------------")
        lines.append(self.var_table_to_string())
        lines.append("")
        lines.append("Expression table")
        lines.append("----------------")
        lines.append(self.xpr_table_to_string())
        return "\n".join(lines)
