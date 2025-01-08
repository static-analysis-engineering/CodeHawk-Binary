# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024-2025 Aarno Labs LLC
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

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.FnXprDictionary import FnXprDictionary
    from chb.invariants.VMemoryOffset import VMemoryOffset
    from chb.invariants.XXpr import XXpr


class GlobalReference:

    def __init__(self,
                 function: "Function",
                 gloc: "GlobalLocation",
                 xnode: ET.Element) -> None:
        self._function = function
        self._gloc = gloc
        self._xnode = xnode

    @property
    def xnode(self) -> ET.Element:
        return self._xnode

    @property
    def mmap(self) -> "GlobalMemoryMap":
        return self._gloc.mmap

    @property
    def app(self) -> "AppAccess":
        return self.mmap.app

    @property
    def function(self) -> "Function":
        return self._function

    @property
    def vardictionary(self) -> "FnVarDictionary":
        return self.function.vardictionary

    @property
    def xprdictionary(self) -> "FnXprDictionary":
        return self.vardictionary.xd

    @property
    def gloc(self) -> "GlobalLocation":
        return self._gloc

    @property
    def gaddr(self) -> str:
        return self.gloc.addr

    @property
    def faddr(self) -> str:
        return self.function.faddr

    @property
    def iaddr(self) -> str:
        iaddr = self._xnode.get("i")
        if iaddr is None:
            raise UF.CHBError("Attribute i is missing for " + self.gaddr)
        return iaddr

    @property
    def grefvalue(self) -> "XXpr":
        xix = self._xnode.get("xix")
        if xix is None:
            raise UF.CHBError("Attribute xix is missing for " + self.gaddr)
        return self.xprdictionary.xpr(int(xix))

    def __str__(self) -> str:
        return "Ref: " + self.gaddr + ": " + str(self.grefvalue)


class GlobalLoad(GlobalReference):

    def __init__(
            self,
            function: "Function",
            gloc: "GlobalLocation",
            xnode: ET.Element) -> None:
        GlobalReference.__init__(self, function, gloc, xnode)

    @property
    def size(self) -> int:
        return int(self.xnode.get("s", "0"))

    def __str__(self) -> str:
        return "Load: " + str(self.grefvalue) + " (" + self.gaddr + ")"


class GlobalStore(GlobalReference):

    def __init__(
            self,
            function: "Function",
            gloc: "GlobalLocation",
            xnode: ET.Element) -> None:
        GlobalReference.__init__(self, function, gloc, xnode)

    @property
    def size(self) -> int:
        return int(self.xnode.get("s", "0"))

    @property
    def value(self) -> Optional[int]:
        optval = self._xnode.get("v")
        if optval is not None:
            return int(optval)
        else:
            return None

    def __str__(self) -> str:
        return "Store: " + str(self.grefvalue) + " (" + self.gaddr + ")"


class GlobalAddressArgument(GlobalReference):

    def __init__(
            self,
            function: "Function",
            gloc: "GlobalLocation",
            xnode: ET.Element) -> None:
        GlobalReference.__init__(self, function, gloc, xnode)

    @property
    def argindex(self) -> int:
        return int(self.xnode.get("aix", "-1"))

    @property
    def memory_offset(self) -> Optional["VMemoryOffset"]:
        mix = self.xnode.get("mix")
        if mix is not None:
            return self.vardictionary.memory_offset(int(mix))
        return None

    def __str__(self) -> str:
        return (
            "Argument: "
            + str(self.grefvalue)
            + " with offset "
            + str(self.memory_offset)
            + " ("
            + self.gaddr
            + ")")


class GlobalLocation:

    def __init__(self, mmap: "GlobalMemoryMap", xnode: ET.Element) -> None:
        self._mmap = mmap
        self._xnode = xnode

    @property
    def mmap(self) -> "GlobalMemoryMap":
        return self._mmap

    @property
    def name(self) -> str:
        return self._xnode.get("name", "?")

    @property
    def addr(self) -> str:
        return self._xnode.get("a", "0x0")

    @property
    def gtype(self) -> Optional["BCTyp"]:
        tix = self._xnode.get("tix", None)
        if tix is not None:
            return self.mmap.bcdictionary.typ(int(tix))
        return None

    @property
    def size(self) -> Optional[int]:
        s = self._xnode.get("size", None)
        if s is not None:
            return int(s)
        else:
            return None


class GlobalMemoryMap:

    def __init__(self, app: "AppAccess", xnode: Optional[ET.Element]) -> None:
        self._app = app
        self._xnode = xnode
        self._locations: Optional[Dict[str, GlobalLocation]] = None

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def bcdictionary(self) -> "BCDictionary":
        return self.app.bcdictionary

    @property
    def deflocnode(self) -> Optional[ET.Element]:
        if self._xnode is not None:
            return self._xnode.find("locations")
        return None

    @property
    def refaddrnode(self) -> Optional[ET.Element]:
        if self._xnode is not None:
            return self._xnode.find("no-locations")
        return None

    @property
    def locations(self) -> Dict[str, GlobalLocation]:
        if self._locations is None:
            self._locations = {}
            if self.deflocnode is not None:
                for xgloc in self.deflocnode.findall("gloc"):
                    addr = xgloc.get("a", "0x0")
                    self._locations[addr] = GlobalLocation(self, xgloc)
        return self._locations

    def get_location_by_name(self, name: str) -> Optional[GlobalLocation]:
        for gloc in self.locations.values():
            if gloc.name == name:
                return gloc
        else:
            return None

    def get_location(self, addr: str) -> Optional[GlobalLocation]:
        if addr in self.locations:
            return self.locations[addr]
        else:
            return None

    def coverage(self) -> Tuple[int, int]:
        loccoverage: int = 0
        loccount: int = 0
        for gloc in self.locations.values():
            size = gloc.size
            if size is not None:
                loccoverage += size
                loccount += 1
        return (loccount, loccoverage)
