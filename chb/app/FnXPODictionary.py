# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023 Aarno Labs LLC
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
"""Dictionary for indexing proof obligation predicates in a single function."""

import xml.etree.ElementTree as ET

from typing import List, Optional, TYPE_CHECKING

from chb.app.FnXPODictionaryRecord import xporegistry, FnXPODictionaryRecord
from chb.app.XPOPredicate import XPOPredicate

import chb.util.IndexedTable as IT
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary
    from chb.app.Function import Function
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.invariants.FnXprDictionary import FnXprDictionary
    from chb.invariants.XXpr import XXpr


class XPOFormatArgument(FnXPODictionaryRecord):

    def __init__(self, xpod: "FnXPODictionary", ixval: IT.IndexedTableValue) -> None:
        FnXPODictionaryRecord.__init__(self, xpod, ixval)

    @property
    def argument(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def converter(self) -> str:
        return self.tags[0]

    @property
    def fieldwidth(self) -> Optional[int]:
        return None if self.tags[1] == "other" else int(self.tags[1])

    def __str__(self) -> str:
        return "(" + self.converter + ", " + str(self.argument) + ")"


class FnXPODictionary:

    def __init__(
            self,
            fn: "Function",
            xnode: ET.Element) -> None:
        self._fn = fn
        self.format_arg_table = IT.IndexedTable("format-arg-table")
        self.xpo_predicate_table = IT.IndexedTable("xpo-predicate-table")
        self.tables: List[IT.IndexedTable] = [
            self.format_arg_table,
            self.xpo_predicate_table
        ]
        self.initialize(xnode)

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def xprdictionary(self) -> "FnXprDictionary":
        return self.function.xprdictionary

    @property
    def bcdictionary(self) -> "BCDictionary":
        return self.function.bcd

    @property
    def bdictionary(self) -> "BDictionary":
        return self.function.bd

    # ------------------------------------------ retrieve items from tables ---

    def xpo_predicate(self, ix: int) -> XPOPredicate:
        if ix > 0:
            return xporegistry.mk_instance(
                self, self.xpo_predicate_table.retrieve(ix), XPOPredicate)
        else:
            raise UF.CHBError(
                "Illegal xpo predicate index value: " + str(ix))

    def format_arg(self, ix: int) -> XPOFormatArgument:
        return XPOFormatArgument(self, self.format_arg_table.retrieve(ix))


    # ------------------------------------- initialize dictionary from file ---

    def read_xml_xpo_predicate(self, xnode: ET.Element) -> XPOPredicate:
        index = xnode.get("ixpo")
        if index is not None:
            return self.xpo_predicate(int(index))
        else:
            raise UF.CHBError("Index ixpo not found in xpo node")

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.reset()
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError(
                    "XPO dictionary table " + t.name + " not found")
        
        
