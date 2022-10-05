# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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

import xml.etree.ElementTree as ET

from typing import List, Optional, Sequence

from chb.app.BDictionary import BDictionary
from chb.app.CallbackTables import CallbackTables
from chb.app.DataBlocks import DataBlocks
from chb.app.FunctionsData import FunctionsData
from chb.app.JumpTables import JumpTables
from chb.app.StringXRefs import StringsXRefs, StringXRefs
from chb.app.StructTables import StructTables

import chb.util.fileutil as UF


class SystemInfo:

    def __init__(
            self,
            bd: BDictionary,
            xnode: ET.Element) -> None:
        self._bd = bd
        self.xnode = xnode
        self._fdata: Optional[FunctionsData] = None
        self._stringxrefs: Optional[StringsXRefs] = None
        self._jumptables: Optional[JumpTables] = None
        self._callbacktables: Optional[CallbackTables] = None
        self._structtables: Optional[StructTables] = None
        self._datablocks: Optional[DataBlocks] = None

    @property
    def bd(self) -> BDictionary:
        return self._bd

    @property
    def functionsdata(self) -> FunctionsData:
        if self._fdata is None:
            xfdata = self.xnode.find("functions-data")
            if xfdata is not None:
                self._fdata = FunctionsData(self.bd, xfdata)
            else:
                raise UF.CHBError("Functions data not found in system-info")
        return self._fdata

    def has_function(self, faddr: str) -> bool:
        return self.functionsdata.has_function(faddr)

    def has_function_name(self, faddr: str) -> bool:
        return self.functionsdata.has_name(faddr)

    def function_name(self, faddr: str) -> str:
        return self.functionsdata.name(faddr)

    def function_names(self, faddr: str) -> Sequence[str]:
        return self.functionsdata.names(faddr)

    def is_app_function_name(self, name: str) -> bool:
        return self.functionsdata.is_app_function_name(name)

    def is_unique_app_function_name(self, name: str) -> bool:
        return self.functionsdata.is_unique_app_function_name(name)

    def function_address_from_name(self, name: str) -> str:
        return self.functionsdata.function_address_from_name(name)

    @property
    def stringsxrefs(self) -> StringsXRefs:
        if self._stringxrefs is None:
            xstrings = self.xnode.find("string-xreferences")
            if xstrings is not None:
                self._stringxrefs = StringsXRefs(self.bd, xstrings)
            else:
                raise UF.CHBError("String xrefs not found in system-info")
        return self._stringxrefs

    @property
    def jumptables(self) -> JumpTables:
        if self._jumptables is None:
            xjumps = self.xnode.find("jumptables")
            if xjumps is not None:
                self._jumptables = JumpTables(xjumps)
            else:
                raise UF.CHBError("Jumptables not found in system info")
        return self._jumptables

    @property
    def callbacktables(self) -> CallbackTables:
        if self._callbacktables is None:
            xtables = self.xnode.find("call-back-tables")
            if xtables is not None:
                self._callbacktables = CallbackTables(xtables)
            else:
                raise UF.CHBError("Callback tables not found in system info")
        return self._callbacktables

    @property
    def structtables(self) -> StructTables:
        if self._structtables is None:
            xtables = self.xnode.find("struct-tables")
            if xtables is not None:
                self._structtables = StructTables(xtables)
            else:
                raise UF.CHBError("Struct tables not found in system info")
        return self._structtables

    @property
    def datablocks(self) -> DataBlocks:
        if self._datablocks is None:
            xdatablocks = self.xnode.find("data-blocks")
            if xdatablocks is not None:
                self._datablocks = DataBlocks(xdatablocks)
            else:
                raise UF.CHBError("Data blocks not found in system info")
        return self._datablocks
