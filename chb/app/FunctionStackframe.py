# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2025  Aarno Labs LLC
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

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary

    from chb.app.Function import Function
    from chb.app.Register import Register
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp
    from chb.invariants.FnStackAccess import FnStackAccess
    from chb.invariants.FnVarDictionary import FnVarDictionary


class Stackslot:

    def __init__(self, stackframe: "FunctionStackframe", xnode: ET.Element) -> None:
        self._stackframe = stackframe
        self._xnode = xnode

    @property
    def stackframe(self) -> "FunctionStackframe":
        return self._stackframe

    @property
    def name(self) -> str:
        return self._xnode.get("name", "no-name")

    @property
    def offset(self) -> int:
        return int(self._xnode.get("offset", "-1"))

    @property
    def size(self) -> Optional[int]:
        size = self._xnode.get("size", None)
        if size is not None:
            return int(size)
        else:
            return None

    @property
    def btype(self) -> Optional["BCTyp"]:
        tix = self._xnode.get("tix", None)
        if tix is not None:
            return self.stackframe.bcdictionary.typ(int(tix))
        return None

    @property
    def spill(self) -> Optional["Register"]:
        srix = self._xnode.get("srix", None)
        if srix is not None:
            return self.stackframe.bdictionary.register(int(srix))
        return None

    @property
    def is_spill(self) -> bool:
        return self.spill is not None

    def __str__(self) -> str:
        pty = " (" + str(self.btype) + ")" if self.btype is not None else ""
        psi = " (size: " + str(self.size) + ")" if self.size is not None else ""
        return self.name + pty + psi


class FunctionStackframe:

    def __init__(self, fn: "Function", xnode: ET.Element) -> None:
        self._fn = fn
        self._xnode = xnode
        self._stackslots: Optional[Dict[int, Stackslot]] = None
        self._accesses: Optional[Dict[int, List[Tuple[str, "FnStackAccess"]]]] = None

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def bdictionary(self) -> "BDictionary":
        return self.function.bd

    @property
    def bcdictionary(self) -> "BCDictionary":
        return self.function.bcd

    @property
    def vardictionary(self) -> "FnVarDictionary":
        return self.function.vardictionary

    @property
    def saved_registers(self) -> Dict[int, "Register"]:
        result: Dict[int, Register] = {}
        for (offset, stackslot) in self.stackslots.items():
            if stackslot.spill is not None:
                result[offset] = stackslot.spill
        return result

    @property
    def stackslots(self) -> Dict[int, Stackslot]:
        if self._stackslots is None:
            self._stackslots = {}
            xsnode = self._xnode.find("stack-slots")
            if xsnode is not None:
                xslots = xsnode.findall("slot")
                for xslot in xslots:
                    stackslot = Stackslot(self, xslot)
                    self._stackslots[stackslot.offset] = stackslot
        return self._stackslots

    def stackslot(self, offset: int) -> Optional[Stackslot]:
        """Returns the stack slot at the given offset.

        Note that the offset is expected to be negative.
        """

        return self.stackslots.get(offset, None)

    @property
    def accesses(self) -> Dict[int, List[Tuple[str, "FnStackAccess"]]]:
        if self._accesses is None:
            self._accesses = {}
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
                            sa = self.vardictionary.read_xml_stack_access(xsa)
                            offsetacc.append((iaddr, sa))
        return self._accesses

    def __str__(self) -> str:
        lines: List[str] = []
        for (offset, stackslot) in sorted(self.stackslots.items(), reverse=True):
            lines.append(str(offset).rjust(5) + "  " + str(stackslot))
            if offset in self.accesses:
                for (iaddr, acc) in self.accesses[offset]:
                    lines.append(" ".rjust(10) + iaddr + ": " + str(acc))
                lines.append("")
        return "\n".join(lines)
