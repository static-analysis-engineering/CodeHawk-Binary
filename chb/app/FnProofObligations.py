# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
"""Proof obligations associated with a single function."""

import xml.etree.ElementTree as ET

from typing import Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.app.Register import Register
from chb.invariants.FnStackAccess import FnStackAccess

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary
    from chb.app.FnXPODictionary import FnXPODictionary
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.app.XPOPredicate import XPOPredicate
    from chb.invariants.FnVarDictionary import FnVarDictionary


class POStatus:

    def __init__(self, tag: str) -> None:
        self._tag = tag

    @property
    def tag(self) -> str:
        return self._tag

    def __str__(self) -> str:
        return self.tag


class ProofObligation:

    def __init__(self, iaddr: str, xpo: "XPOPredicate", status: POStatus) -> None:
        self._iaddr = iaddr
        self._xpo = xpo
        self._status = status

    @property
    def iaddr(self) -> str:
        return self._iaddr

    @property
    def xpo(self) -> "XPOPredicate":
        return self._xpo

    @property
    def status(self) -> POStatus:
        return self._status

    def __str__(self) -> str:
        return self.iaddr + ": " + str(self.xpo) + " (" + str(self.status) + ")"


class FnProofObligations:

    def __init__(self, fn: "Function", xnode: ET.Element) -> None:
        self._fn = fn
        self._xnode = xnode
        self._store: Dict[str, List[ProofObligation]] = {}

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def xpod(self) -> "FnXPODictionary":
        return self.function.xpodictionary

    @property
    def proofobligations(self) -> Dict[str, List[ProofObligation]]:
        if len(self._store) == 0:
            for xloc in self._xnode.findall("loc"):
                iaddr = xloc.get("ia")
                if iaddr is not None:
                    self._store[iaddr] = []
                    for xxpo in xloc.findall("po"):
                        xpo = self.xpod.read_xml_xpo_predicate(xxpo)
                        statustag = xxpo.get("s", "o")
                        status = POStatus(statustag)
                        po = ProofObligation(iaddr, xpo, status)
                        self._store[iaddr].append(po)
        return self._store

    def __str__(self) -> str:
        lines: List[str] = []
        for (loc, polist) in sorted(self.proofobligations.items()):
            lines.append(loc)
            for po in polist:
                lines.append("  " + str(po))
        return "\n".join(lines)
                        
                        
