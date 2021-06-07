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

from chb.invariants.InvariantFact import InvariantFact
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.invariants.FnInvDictionary import FnInvDictionary


class FnInvariants:

    def __init__(
            self,
            invd: "FnInvDictionary",
            xnode: ET.Element) -> None:
        self._invd = invd
        self.xnode = xnode
        self._invariants: Dict[str, List[InvariantFact]] = {}

    @property
    def invd(self) -> "FnInvDictionary":
        return self._invd

    '''
    @property
    def function(self) -> "chb.app.Function.Function":
        return self.invd.function
    '''

    @property
    def invariants(self) -> Mapping[str, Sequence[InvariantFact]]:
        if len(self._invariants) == 0:
            for xloc in self.xnode.findall("loc"):
                ia = xloc.get("a")
                ifacts = xloc.get("ifacts")
                if ia is not None and ifacts is not None:
                    self._invariants[ia] = []
                    for findex in [int(x) for x in ifacts.split(",")]:
                        self._invariants[ia].append(
                            self.invd.invariant_fact(findex))
                else:
                    raise UF.CHBError("address or facts missing")
        return self._invariants

    def loc_invariants(self, addr: str) -> Sequence[InvariantFact]:
        """Return the invariants for a particular location."""

        if addr in self.invariants:
            return self.invariants[addr]
        else:
            raise UF.CHBError("No invariant found for " + addr)

    def has_invariant(self, addr: str) -> bool:
        return addr in self.invariants

    def __str__(self) -> str:
        lines: List[str] = []
        for loc in sorted(self.invariants):
            lines.append(str(loc) + ': ')
            locinv = self.invariants[loc]
            for i in locinv:
                lines.append('  ' + str(i))
        return '\n'.join(lines)
