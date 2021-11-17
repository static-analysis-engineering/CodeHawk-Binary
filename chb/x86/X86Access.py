# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from chb.elfformat.ELFHeader import ELFHeader
from typing import Dict, List, Mapping, Optional, Sequence, Type

from chb.app.Callgraph import Callgraph
from chb.app.AppAccess import AppAccess, HeaderTy

import chb.util.fileutil as UF

from chb.x86.X86Dictionary import X86Dictionary
from chb.x86.X86Function import X86Function
from chb.x86.X86Instruction import X86Instruction


class X86Access(AppAccess[HeaderTy]):

    def __init__(
            self,
            path: str,
            filename: str,
            fileformat: Type[HeaderTy],
            deps: List[str] = []) -> None:
        AppAccess.__init__(self, path, filename, fileformat, deps)
        self._x86d: Optional[X86Dictionary] = None
        self._functions: Dict[str, X86Function] = {}

    @property
    def is_x86(self) -> bool:
        return True

    @property
    def x86dictionary(self) -> X86Dictionary:
        if self._x86d is None:
            x = UF.get_x86_dictionary_xnode(self.path, self.filename)
            self._x86d = X86Dictionary(self, x)
        return self._x86d

    @property
    def functions(self) -> Mapping[str, X86Function]:
        if len(self._functions) == 0:
            for faddr in self.appfunction_addrs:
                xnode = UF.get_function_results_xnode(
                    self.path, self.filename, faddr)
                self._functions[faddr] = X86Function(
                    self.path,
                    self.filename,
                    self.bdictionary,
                    self.interfacedictionary,
                    self.function_info(faddr),
                    self.x86dictionary,
                    self.stringsxrefs,
                    self.function_names(faddr),
                    self.models,
                    xnode)
        return self._functions

    @property
    def call_edges(self) -> Mapping[str, Mapping[str, int]]:
        return {}

    @property
    def max_address(self) -> str:
        raise UF.CHBNotImplementedError("X86Access", "max_address", "")
