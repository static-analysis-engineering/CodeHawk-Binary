# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
from typing import Dict, List, Mapping, Optional

from chb.app.AppAccess import AppAccess, HeaderTy

from chb.arm.ARMDictionary import ARMDictionary
from chb.arm.ARMFunction import ARMFunction

import chb.util.fileutil as UF


class ARMAccess(AppAccess[HeaderTy]):

    def __init__(
            self,
            path: str,
            filename: str,
            deps: List[str] = [],
            fileformat: HeaderTy = ELFHeader,
            arch: str = "arm") -> None:
        AppAccess.__init__(self, path, filename, deps, fileformat, arch)
        self._armd: Optional[ARMDictionary] = None
        self._functions: Dict[str, ARMFunction] = {}

    @property
    def armdictionary(self) -> ARMDictionary:
        if self._armd is None:
            x = UF.get_arm_dictionary_xnode(self.path, self.filename)
            self._armd = ARMDictionary(self, x)
        return self._armd

    @property
    def functions(self) -> Mapping[str, ARMFunction]:
        if len(self._functions) == 0:
            for faddr in self.appfunction_addrs:
                xnode = UF.get_function_results_xnode(
                    self.path, self.filename, faddr)
                self._functions[faddr] = ARMFunction(
                    self.path,
                    self.filename,
                    self.bdictionary,
                    self.interfacedictionary,
                    self.function_info(faddr),
                    self.armdictionary,
                    self.stringsxrefs,
                    self.function_names(faddr),
                    xnode)
        return self._functions

    def call_edges(self) -> Mapping[str, Mapping[str, int]]:
        return {}
