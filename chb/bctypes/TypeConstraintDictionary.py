# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs LLC
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

from typing import List, Optional, TYPE_CHECKING

import chb.bctypes.TypeConstraint as TC
from chb.bctypes.TypeConstraintDictionaryRecord import tcdregistry

import chb.util.IndexedTable as IT
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BDictionary import BDictionary


class TypeConstraintDictionary:

    def __init__(self, app: "AppAccess", xnode: Optional[ET.Element]) -> None:
        self._app = app
        self.type_basevar_table = IT.IndexedTable("type-base-variable")
        self.type_caplabel_table = IT.IndexedTable("type-cap-label-table")
        self.type_variable_table = IT.IndexedTable("type-variable-table")
        self.type_constant_table = IT.IndexedTable("type-constant-table")
        self.type_term_table = IT.IndexedTable("type-term-table")
        self.type_constraint_table = IT.IndexedTable("type-constraint-table")

        self.tables = [
            self.type_basevar_table,
            self.type_caplabel_table,
            self.type_variable_table,
            self.type_constant_table,
            self.type_term_table,
            self.type_constraint_table
        ]
        self._initialize(xnode)

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def bdictionary(self) -> "BDictionary":
        return self.app.bdictionary

    def type_constraints(self) -> List[TC.TypeConstraint]:
        return [
            self.type_constraint(ix)
            for ix in self.type_constraint_table.keys()]

    # ------------- Retrieve items from dictionary tables ----------------------

    def type_basevar(self, ix: int) -> TC.TypeBaseVariable:
        return tcdregistry.mk_instance(
            self, self.type_basevar_table.retrieve(ix), TC.TypeBaseVariable)

    def type_cap_label(self, ix: int) -> TC.TypeCapLabel:
        return tcdregistry.mk_instance(
            self, self.type_caplabel_table.retrieve(ix), TC.TypeCapLabel)

    def type_cap_label_list(self, ixs: List[int]) -> List[TC.TypeCapLabel]:
        return [self.type_cap_label(ix) for ix in ixs]

    def type_variable(self, ix: int) -> TC.TypeVariable:
        return TC.TypeVariable(self, self.type_variable_table.retrieve(ix))

    def type_constant(self, ix: int) -> TC.TypeConstant:
        return tcdregistry.mk_instance(
            self, self.type_constant_table.retrieve(ix), TC.TypeConstant)

    def type_term(self, ix: int) -> TC.TypeTerm:
        return tcdregistry.mk_instance(
            self, self.type_term_table.retrieve(ix), TC.TypeTerm)

    def type_constraint(self, ix: int) -> TC.TypeConstraint:
        return tcdregistry.mk_instance(
            self, self.type_constraint_table.retrieve(ix), TC.TypeConstraint)

    # ---------------------- Initialize dictionary from file -------------------

    def _initialize(self, xnode: Optional[ET.Element]) -> None:
        if xnode is not None:
            for t in self.tables:
                xtable = xnode.find(t.name)
                if xtable is not None:
                    t.reset()
                    t.read_xml(xtable, "n")
                else:
                    raise UF.CHBError(
                        "Table "
                        + t.name
                        + " not found in type constraint dictionary")
