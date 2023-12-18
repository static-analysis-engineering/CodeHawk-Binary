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
"""Stackframe layout obtained from the ocaml analyzer."""

import xml.etree.ElementTree as ET

from typing import Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.app.Register import Register
from chb.invariants.FnStackAccess import FnStackAccess

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.invariants.FnVarDictionary import FnVarDictionary


class FnSavedRegister:

    def __init__(self, reg: Register, xnode: ET.Element) -> None:
        self._reg = reg
        self._xnode = xnode

    @property
    def register(self) -> Register:
        return self._reg

    @property
    def save_locations(self) -> List[str]:
        xsave = self._xnode.get("save")
        if xsave is None:
            return []
        else:
            return xsave.split(";")

    @property
    def restore_locations(self) -> List[str]:
        xrestore = self._xnode.get("restore")
        if xrestore is None:
            return []
        else:
            return xrestore.split(";")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("register: " + str(self.register))
        lines.append("  save locations: " + ", ".join(self.save_locations))
        lines.append("  restore locations: " + ", ".join(self.restore_locations))
        return "\n".join(lines)


class FnStackFrame:

    def __init__(self, fn: "Function", xnode: ET.Element) -> None:
        self._fn = fn
        self._xnode = xnode
        self._savedregisters: Dict[str, FnSavedRegister] = {}
        self._accesses: Dict[int, List[Tuple[str, FnStackAccess]]] = {}

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def bd(self) -> "BDictionary":
        return self.function.bd

    @property
    def vard(self) -> "FnVarDictionary":
        return self.function.vardictionary

    @property
    def saved_registers(self) -> Dict[str, FnSavedRegister]:
        if len(self._savedregisters) == 0:
            srnode = self._xnode.find("saved-registers")
            if srnode is not None:
                for xrs in srnode.findall("sr"):
                    reg = self.bd.read_xml_register(xrs)
                    sr = FnSavedRegister(reg, xrs)
                    self._savedregisters[str(reg)] = sr
        return self._savedregisters

    @property
    def accesses(self) -> Dict[int, List[Tuple[str, FnStackAccess]]]:
        if len(self._accesses) == 0:
            sanode = self._xnode.find("stack-accesses")
            if sanode is not None:
                for xoff in sanode.findall("offset"):
                    offset = xoff.get("n")
                    if offset is not None:
                        stackoffset = int(offset)
                        offsetacc: List[Tuple[str, FnStackAccess]] = []
                        self._accesses[stackoffset] = offsetacc
                        for xsa in xoff.findall("sa"):
                            iaddr = xsa.get("addr", "0x0")
                            sa = self.vard.read_xml_stack_access(xsa)
                            offsetacc.append((iaddr, sa))
        return self._accesses

    def __str__(self) -> str:
        lines: List[str] = []
        for offset in sorted(self.accesses):
            lines.append(str(offset))
            offsetacc = self.accesses[offset]
            for (iaddr, acc) in offsetacc:
                lines.append("  " + iaddr + ": " + str(acc))
        return "\n".join(lines)
            

    
