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
from typing import Callable, Type, cast, Dict, List, Mapping, Optional, Sequence, Tuple

from chb.api.CallTarget import CallTarget, IndirectTarget

from chb.app.Callgraph import Callgraph, mk_tgt_callgraph_node, mk_app_callgraph_node
from chb.app.AppAccess import AppAccess, HeaderTy

from chb.mips.MIPSDictionary import MIPSDictionary
from chb.mips.MIPSFunction import MIPSFunction
from chb.mips.MIPSInstruction import MIPSInstruction

import chb.util.fileutil as UF


class MIPSAccess(AppAccess[HeaderTy]):

    def __init__(
            self,
            path: str,
            filename: str,
            fileformat: Type[HeaderTy],
            deps: List[str] = []) -> None:
        AppAccess.__init__(self, path, filename, fileformat, deps)
        self._mipsd: Optional[MIPSDictionary] = None
        self._functions: Dict[str, MIPSFunction] = {}
        self._callgraph: Optional[Callgraph] = None
        self._maxaddr: Optional[str] = "0x600000"    # for testing purposes

    @property
    def is_mips(self) -> bool:
        return True

    @property
    def mipsdictionary(self) -> MIPSDictionary:
        if self._mipsd is None:
            x = UF.get_mips_dictionary_xnode(self.path, self.filename)
            self._mipsd = MIPSDictionary(self, x)
        return self._mipsd

    def function(self, faddr: str) -> MIPSFunction:
        return cast(MIPSFunction, AppAccess.function(self, faddr))

    @property
    def functions(self) -> Mapping[str, MIPSFunction]:
        if len(self._functions) == 0:
            for faddr in self.appfunction_addrs:
                xnode = UF.get_function_results_xnode(
                    self.path, self.filename, faddr)
                self._functions[faddr] = MIPSFunction(
                    self.path,
                    self.filename,
                    self.bcdictionary,
                    self.bdictionary,
                    self.interfacedictionary,
                    self.function_info(faddr),
                    self.mipsdictionary,
                    self.stringsxrefs,
                    self.function_names(faddr),
                    self.models,
                    xnode)
        return self._functions

    def iter_functions(self, f: Callable[[str, MIPSFunction], None]) -> None:
        for (faddr, fn) in sorted(self.functions.items()):
            f(faddr, fn)

    def address_reference(self) -> Mapping[str, Tuple[str, List[str]]]:
        """Return map of addr -> [ baddr, [ faddr ])."""

        result: Dict[str, Tuple[str, List[str]]] = {}

        def add(faddr: str, fn: MIPSFunction) -> None:
            fnref = fn.address_reference   # addr -> baddr
            for a in fnref:
                if a in result:
                    result[a][1].append(faddr)
                else:
                    result[a] = (fnref[a], [faddr])

        self.iter_functions(add)
        return result

    @property
    def max_address(self) -> str:
        """Return the maximum address in the address space (in hex)."""

        if not self._maxaddr:
            result = 0

            for (faddr, f) in self.functions.items():
                for loc in f.invariants:
                    for fact in f.invariants[loc]:
                        if fact.is_nonrelational and str(fact.variable) == "$gp":
                            if fact.value.is_singleton:
                                if fact.value.singleton_value > result:
                                    result = fact.value.singleton_value
            self._maxaddr = hex(result)

        return self._maxaddr
