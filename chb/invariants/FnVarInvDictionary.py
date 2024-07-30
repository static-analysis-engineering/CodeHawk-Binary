# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Variable Invariant dictionary local to a particular function."""

import xml.etree.ElementTree as ET

from typing import Callable, cast, List, Optional, Set, Tuple, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import varinvregistry
from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnXprDictionary import FnXprDictionary
from chb.invariants.VarDefUse import VarDefUse
from chb.invariants.VarInvariantFact import VarInvariantFact

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.invariants.VarInvariantFact import ReachingDefFact
    from chb.invariants.XVariable import XVariable


class FnVarInvDictionary:

    def __init__(
            self,
            vd: FnVarDictionary,
            xnode: Optional[ET.Element]) -> None:

        self._vd = vd
        self.xnode = xnode
        self.vardefuse_table = IT.IndexedTable("vardefuse-table")
        self.var_invariant_fact_table = IT.IndexedTable("var-invariant-fact-table")
        self.tables: List[IT.IndexedTable] = [
            self.vardefuse_table,
            self.var_invariant_fact_table
        ]
        self.initialize(xnode)

    @property
    def vd(self) -> FnVarDictionary:
        return self._vd

    @property
    def xd(self) -> FnXprDictionary:
        return self.vd.xd

    @property
    def function(self) -> "Function":
        return self.vd.function

    # ----------------------------- Retrieve items from dictionary tables ------

    def vardefuse(self, ix: int) -> VarDefUse:
        if ix > 0:
            return VarDefUse(
                self, self.vardefuse_table.retrieve(ix))
        else:
            raise UF.CHBError(
                "Illegal vardefuse index value: " + str(ix))

    def var_invariant_fact(self, ix: int) -> VarInvariantFact:
        if ix > 0:
            return varinvregistry.mk_instance(
                self,
                self.var_invariant_fact_table.retrieve(ix),
                VarInvariantFact)
        else:
            raise UF.CHBError(
                "Illegal var-invariant-fact index value: " + str(ix))

    # ----------------------------- Initialize dictionary from file ------------

    def initialize(self, xnode: Optional[ET.Element]) -> None:
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
                        + " is missing from varinvariant dictionary")

    # ------------------------------------------------------ Printing ----------

    def var_invariant_fact_table_to_string(self) -> str:
        lines: List[str] = []

        def f(ix: int, v: IT.IndexedTableValue) -> None:
            lines.append(str(ix) + ": " + str(self.var_invariant_fact(ix)))

        self.var_invariant_fact_table.iter(f)
        return "\n".join(lines)
