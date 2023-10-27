# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs LLC
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


from typing import Callable, Dict, List, Mapping, Optional, Type

from chb.app.Callgraph import Callgraph, mk_tgt_callgraph_node, mk_app_callgraph_node
from chb.app.AppAccess import AppAccess, HeaderTy

from chb.elfformat.ELFHeader import ELFHeader

from chb.pwr.PowerDictionary import PowerDictionary
from chb.pwr.PowerFunction import PowerFunction

import chb.util.fileutil as UF


class PowerAccess(AppAccess[HeaderTy]):

    def __init__(
            self,
            path: str,
            filename: str,
            fileformat: Type[HeaderTy],
            deps: List[str] = []) -> None:
        AppAccess.__init__(self, path, filename, fileformat, deps)
        self._pwrd: Optional[PowerDictionary] = None
        self._functions: Dict[str, PowerFunction] = {}
        self._callgraph: Optional[Callgraph] = None

    @property
    def is_power(self) -> bool:
        return True

    @property
    def pwrdictionary(self) -> PowerDictionary:
        if self._pwrd is None:
            x = UF.get_pwr_dictionary_xnode(self.path, self.filename)
            self._pwrd = PowerDictionary(self, x)
        return self._pwrd

    @property
    def functions(self) -> Mapping[str, PowerFunction]:
        if len(self._functions) == 0:
            for faddr in self.appfunction_addrs:
                xnode = UF.get_function_results_xnode(
                    self.path, self.filename, faddr)
                self._functions[faddr] = PowerFunction(
                    self.path,
                    self.filename,
                    self.bcdictionary,
                    self.bdictionary,
                    self.interfacedictionary,
                    self.function_info(faddr),
                    self.pwrdictionary,
                    self.stringsxrefs,
                    self.function_names(faddr),
                    xnode)
        return self._functions

    def iter_functions(self, f: Callable[[str, PowerFunction], None]) -> None:
        for (faddr, fn) in sorted(self.functions.items()):
            f(faddr, fn)

    def call_edges(self) -> Mapping[str, Mapping[str, int]]:
        return {}

    @property
    def max_address(self) -> str:
        raise UF.CHBNotImplementedError("PowerAccess", "max_address", "")
