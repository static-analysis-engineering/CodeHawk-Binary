# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

import xml.etree.ElementTree as ET

from typing import Dict, List, Mapping, Sequence, Tuple, TYPE_CHECKING

from chb.app.BDictionary import BDictionary

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess


class FunctionData:

    """
    rep-record representation
    id: function address (decimal)
    tags: (all optional)
          'l': library stub
          'nr': non-returning
          'nc': not-complete
          'ida': provided by IDA Pro
          'pre': obtained by preamble
          'u': user-provided
          'v': virtual
          'c': member of a c++ class
    args: if 'c' in tags:
            0: classname
            1: isstatic member
            2+: names   (string-index)
          else:
            0+: names   (string-index)
    """

    def __init__(self,
                 bd: BDictionary,
                 xnode: ET.Element) -> None:
        self._bd = bd
        self.xnode = xnode

    @property
    def bd(self) -> BDictionary:
        return self._bd

    @property
    def rep(self) -> Tuple[int, Sequence[str], Sequence[int]]:
        return IT.get_rep(self.xnode, indextag="id")

    @property
    def id(self) -> int:
        return self.rep[0]

    @property
    def tags(self) -> Sequence[str]:
        return self.rep[1]

    @property
    def args(self) -> Sequence[int]:
        return self.rep[2]

    @property
    def faddr(self) -> str:
        return str(hex(self.id))

    def is_class_member(self) -> bool:
        return 'c' in self.tags

    def is_by_preamble(self) -> bool:
        return 'pre' in self.tags

    def is_library_stub(self) -> bool:
        return 'l' in self.tags

    def has_name(self) -> bool:
        return len(self.names()) > 0

    def name(self) -> str:
        if len(self.names()) > 0:
            return self.names()[0]
        else:
            return self.faddr

    def names(self) -> Sequence[str]:
        if self.is_class_member():
            return [self.bd.string(i) for i in self.args[2:]]
        else:
            return [self.bd.string(i) for i in self.args]

    def __str__(self) -> str:
        names = self.names()
        pnames = ""
        if len(names) > 0:
            pnames = ' (' + ','.join(names) + ')'
        return self.faddr + pnames


class FunctionsData:

    def __init__(
            self,
            bd: BDictionary,
            xnode: ET.Element) -> None:
        self._bd = bd
        self.xnode = xnode
        self._functions: Dict[str, FunctionData] = {}
        self._functionnames: Dict[str, List[str]] = {}

    @property
    def bd(self) -> BDictionary:
        return self._bd

    @property
    def functions(self) -> Mapping[str, FunctionData]:
        if len(self._functions) == 0:
            for x in self.xnode.findall("n"):
                fd = FunctionData(self.bd, x)
                self._functions[fd.faddr] = fd
        return self._functions

    @property
    def functionnames(self) -> Mapping[str, Sequence[str]]:
        if len(self._functionnames) == 0:
            for (faddr, f) in self.functions.items():
                for n in f.names():
                    self._functionnames.setdefault(n, [])
                    self._functionnames[n].append(faddr)
        return self._functionnames

    def has_function(self, faddr: str) -> bool:
        return faddr in self.functions

    def has_name(self, faddr: str) -> bool:
        if faddr in self.functions:
            return self.functions[faddr].has_name()
        else:
            return False

    def name(self, faddr: str) -> str:
        if self.has_name(faddr):
            return self.functions[faddr].names()[0]
        else:
            raise UF.CHBError("Function at " + faddr + " does not have a name")

    def names(self, faddr: str) -> Sequence[str]:
        if self.has_name(faddr):
            return self.functions[faddr].names()
        else:
            return []

    def is_app_function_name(self, name: str) -> bool:
        return name in self.functionnames

    def is_unique_app_function_name(self, name: str) -> bool:
        return (name in self.functionnames
                and len(self.functionnames[name]) == 1)

    def function_address_from_name(self, name: str) -> str:
        if self.is_unique_app_function_name(name):
            return self.functionnames[name][0]
        else:
            raise UF.CHBError("No function found with name " + name)

    def library_stubs(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for f in self.functions.values():
            if f.is_library_stub():
                result[f.faddr] = f.name()
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for fd in sorted(self.functions):
            lines.append(str(self.functions[fd]))
        return '\n'.join(lines)
