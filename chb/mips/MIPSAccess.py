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
                    self.bdictionary,
                    self.interfacedictionary,
                    self.function_info(faddr),
                    self.mipsdictionary,
                    self.stringsxrefs,
                    self.function_names(faddr),
                    self.models,
                    xnode)
        return self._functions

    @property
    def call_edges(self) -> Mapping[str, Mapping[str, int]]:
        return {}

    def iter_functions(self, f: Callable[[str, MIPSFunction], None]) -> None:
        for (faddr, instr) in sorted(self.functions.items()):
            f(faddr, instr)

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

    def app_calls(self) -> Dict[str, List[MIPSInstruction]]:
        """Returns a dictionary faddr -> MIPSInstruction."""
        result: Dict[str, List[MIPSInstruction]] = {}

        def f(faddr: str, fn: MIPSFunction) -> None:
            appcalls = fn.app_calls()
            if len(appcalls) > 0:
                result[faddr] = appcalls

        self.iter_functions(f)
        return result
