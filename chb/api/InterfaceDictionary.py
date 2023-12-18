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
"""Dictionary for indexing data structures related to interprocedural analysis."""

import xml.etree.ElementTree as ET

from typing import List, TYPE_CHECKING

from chb.api.BTerm import BTerm
from chb.api.FtsParameter import FtsParameter
from chb.api.FtsParameterLocation import FtsParameterLocation
from chb.api.AppFunctionInterface import AppFunctionInterface
from chb.api.AppFunctionSemantics import AppFunctionSemantics
from chb.api.AppFunctionSignature import AppFunctionSignature
from chb.api.CallTarget import CallTarget
from chb.api.FunctionStub import FunctionStub
from chb.api.XXPredicate import XXPredicate

from chb.api.InterfaceDictionaryRecord import apiregistry

import chb.util.IndexedTable as IT
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BDictionary import BDictionary
    from chb.bctypes.BCDictionary import BCDictionary


class InterfaceDictionary:

    def __init__(
            self,
            app: "AppAccess",
            xnode: ET.Element) -> None:
        self._app = app
        self.function_stub_table = IT.IndexedTable("function-stub-table")
        self.call_target_table = IT.IndexedTable("call-target-table")
        self.parameter_location_table = IT.IndexedTable("parameter-location-table")
        self.fts_parameter_list_table = IT.IndexedTable("fts-parameter-list-table")
        self.fts_parameter_table = IT.IndexedTable("fts-parameter-table")
        self.function_interface_table = IT.IndexedTable("function-interface-table")
        self.function_semantics_table = IT.IndexedTable("function-semantics-table")
        self.function_signature_table = IT.IndexedTable("function-signature-table")
        self.xxpredicate_list_table = IT.IndexedTable("xxpredicate-list-table")
        self.xxpredicate_table = IT.IndexedTable("xxpredicate-table")
        self.bterm_table = IT.IndexedTable("bterm-table")
        self.tables: List[IT.IndexedTable] = [
            self.parameter_location_table,
            self.function_stub_table,
            self.call_target_table,
            self.function_interface_table,
            self.function_semantics_table,
            self.function_signature_table,
            self.fts_parameter_list_table,
            self.fts_parameter_table,
            self.xxpredicate_list_table,
            self.xxpredicate_table,
            self.bterm_table
        ]
        self.initialize(xnode)

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def bdictionary(self) -> "BDictionary":
        return self.app.bdictionary

    @property
    def bcdictionary(self) -> "BCDictionary":
        return self.app.bcdictionary

    # -------------- Retrieve items from dictionary tables ---------------------

    def parameter_location(self, ix: int) -> FtsParameterLocation:
        return apiregistry.mk_instance(
            self, self.parameter_location_table.retrieve(ix), FtsParameterLocation)

    def function_stub(self, ix: int) -> FunctionStub:
        return apiregistry.mk_instance(
            self, self.function_stub_table.retrieve(ix), FunctionStub)

    def call_target(self, ix: int) -> CallTarget:
        return apiregistry.mk_instance(
            self, self.call_target_table.retrieve(ix), CallTarget)

    def function_interface(self, ix: int) -> AppFunctionInterface:
        return AppFunctionInterface(
            self, self.function_interface_table.retrieve(ix))

    def function_semantics(self, ix: int) -> AppFunctionSemantics:
        return AppFunctionSemantics(
            self, self.function_semantics_table.retrieve(ix))

    def function_signature(self, ix: int) -> AppFunctionSignature:
        return AppFunctionSignature(
            self, self.function_signature_table.retrieve(ix))

    def fts_parameter_list(self, ix: int) -> List[FtsParameter]:
        params = self.fts_parameter_list_table.retrieve(ix).args
        return [self.fts_parameter(ix) for ix in params]

    def fts_parameter(self, ix: int) -> FtsParameter:
        return FtsParameter(self, self.fts_parameter_table.retrieve(ix))

    def xpredicate(self, ix) -> XXPredicate:
        return apiregistry.mk_instance(
            self, self.xxpredicate_table.retrieve(ix), XXPredicate)

    def xpredicate_list(self, ix: int) -> List[XXPredicate]:
        preixs = self.xxpredicate_list_table.retrieve(ix).args
        return [apiregistry.mk_instance(
            self, self.xxpredicate_table.retrieve(ix), XXPredicate)
                for ix in preixs]

    def bterm(self, ix: int) -> BTerm:
        return apiregistry.mk_instance(
            self, self.bterm_table.retrieve(ix), BTerm)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_call_target(self, n: ET.Element) -> CallTarget:
        index = n.get("ictgt")
        if index is not None:
            return self.call_target(int(index))
        else:
            raise UF.CHBError("Index ictgt not found in call target node")

    def read_xml_function_interface(self, n:ET.Element) -> AppFunctionInterface:
        index = n.get("fintf")
        if index is not None:
            return self.function_interface(int(index))
        else:
            raise UF.CHBError("Index fintf not found in summary node")

    def read_xml_function_semantics(self, n: ET.Element) -> AppFunctionSemantics:
        index = n.get("fsem")
        if index is not None:
            return self.function_semantics(int(index))
        else:
            raise UF.CHBError("Index fsem not found in summary node")

    # ---------------- Initialize dictionary from file -------------------------

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            t.reset()
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError(
                    "Table "
                    + t.name
                    + " not found in interface dictionary")
