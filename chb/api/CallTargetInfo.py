# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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
"""Information associated with a call target (target interface, semantics)."""

from typing import cast, List, Optional, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import (
    InterfaceDictionaryRecord, apiregistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.AppFunctionInterface import AppFunctionInterface
    from chb.api.AppFunctionSemantics import AppFunctionSemantics
    from chb.api.CallTarget import CallTarget
    from chb.api.InterfaceDictionary import InterfaceDictionary


class CallTargetInfo:

    def __init__(
            self,
            calltarget: "CallTarget",
            targetinterface: "AppFunctionInterface",
            targetsemantics: "AppFunctionSemantics"
    ) -> None:
        self._tgt = calltarget
        self._fintf = targetinterface
        self._fsem = targetsemantics

    @property
    def calltarget(self) -> "CallTarget":
        return self._tgt

    @property
    def target_interface(self) -> "AppFunctionInterface":
        return self._fintf

    @property
    def target_semantics(self) -> "AppFunctionSemantics":
        return self._fsem

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("  " + str(self.calltarget))
        lines.append("    " + str(self.target_interface))
        lines.append("    " + str(self.target_semantics))
        return "\n".join(lines)
                     
