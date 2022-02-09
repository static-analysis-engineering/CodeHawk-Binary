# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs, LLC
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
"""Creates a mapping of functions between two executables."""

from typing import Dict, List, Mapping, Sequence, Set, Tuple, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Callgraph import Callgraph
    from chb.app.Function import Function


class CallgraphMatcher:

    def __init__(
            self,
            app1: "AppAccess",
            faddrs1: Sequence[str],
            callgraph1: "Callgraph",
            app2: "AppAccess",
            faddrs2: Sequence[str],
            callgraph2: "Callgraph",
            usermapping: Dict[str, str] = {}) -> None:
        self._app1 = app1
        self._app2 = app2
        self._faddrs1 = faddrs1
        self._faddrs2 = faddrs2
        self._callgraph1 = callgraph1
        self._callgraph2 = callgraph2
        self._usermapping = usermapping
        self._fnmd5s: Dict[str, Tuple[List[str], List[str]]] = {}
        self._fnnames: Dict[str, Tuple[List[str], List[str]]] = {}
        self._fnmapping: Dict[str, str] = {}
        self.match()

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def faddrs1(self) -> Sequence[str]:
        return self._faddrs1

    @property
    def faddrs2(self) -> Sequence[str]:
        return self._faddrs2

    @property
    def callgraph1(self) -> "Callgraph":
        return self._callgraph1

    @property
    def callgraph2(self) -> "Callgraph":
        return self._callgraph2

    @property
    def usermapping(self) -> Dict[str, str]:
        return self._usermapping

    @property
    def function_mapping(self) -> Dict[str, str]:
        return self._fnmapping

    def match_md5s(self) -> None:
        for faddr1 in self.faddrs1:
            fn1 = self.app1.function(faddr1)
            md5 = fn1.md5
            self._fnmd5s.setdefault(md5, ([], []))
            self._fnmd5s[md5][0].append(faddr1)
        for faddr2 in self.faddrs2:
            fn2 = self.app2.function(faddr2)
            md5 = fn2.md5
            self._fnmd5s.setdefault(md5, ([], []))
            self._fnmd5s[md5][1].append(faddr2)
        for (f1s, f2s) in self._fnmd5s.values():
            if len(f1s) == 1 and len(f2s) == 1:
                self._fnmapping[f1s[0]] = f2s[0]

    def match_names(self) -> None:
        for faddr1 in self.faddrs1:
            if faddr1 in self._fnmapping:
                pass
            if self.app1.has_function_name(faddr1):
                fname1 = self.app1.function_name(faddr1)
                self._fnnames.setdefault(fname1, ([], []))
                self._fnnames[fname1][0].append(faddr1)
        for faddr2 in self.faddrs2:
            if self.app2.has_function_name(faddr2):
                fname2 = self.app2.function_name(faddr2)
                self._fnnames.setdefault(fname2, ([], []))
                self._fnnames[fname2][1].append(faddr2)
        for (f1s, f2s) in self._fnnames.values():
            if len(f1s) == 1 and len(f2s) == 1:
                self._fnmapping[f1s[0]] = f2s[0]

    def match(self) -> None:
        # initialize with user mapping
        for faddr1 in self.usermapping:
            self._fnmapping[faddr1] = self.usermapping[faddr1]
        self.match_md5s()
        self.match_names()
        # for faddr1 in self.faddrs1:
        #    if faddr1 not in self._fnmapping and faddr1 in self.faddrs2:
        #        self._fnmapping[faddr1] = faddr1
