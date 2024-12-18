# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024 Aarno Labs LLC
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

from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp


class GlobalReference:

    def __init__(self, grefaddr: str, mmap: "GlobalMemoryMap") -> None:
        self._mmap = mmap
        self._grefaddr = grefaddr

    @property
    def mmap(self) -> "GlobalMemoryMap":
        return self._mmap

    @property
    def app(self) -> "AppAccess":
        return self.mmap.app

    @property
    def grefaddr(self) -> str:
        return self._grefaddr

    def __str__(self) -> str:
        return "Ref: " + self.grefaddr

    
class GlobalLoad(GlobalReference):

    def __init__(
            self,
            grefaddr: str,
            mmap: "GlobalMemoryMap",
            xnode: ET.Element) -> None:
        GlobalReference.__init__(self, grefaddr, mmap)
        self._xnode = xnode

    @property
    def gaddr(self) -> str:
        return self._xnode.get("a", self.grefaddr)

    @property
    def instr(self) -> str:
        return self._xnode.get("i", "0x0")

    @property
    def function(self) -> "Function":
        return self.app.function(self.faddr)

    @property
    def faddr(self) -> str:
        return self._xnode.get("f", "0x0")

    @property
    def size(self) -> int:
        return int(self._xnode.get("s", "0"))

    def __str__(self) -> str:
        if self.grefaddr == self.gaddr:
            return "Load: " + str(self.size)
        else:
            offset = int(self.gaddr, 16) - int(self.grefaddr, 16)
            return "Load[" + str(offset) + "]: " + str(self.size)


class GlobalStore(GlobalReference):

    def __init__(
            self,
            grefaddr: str,
            mmap: "GlobalMemoryMap",
            xnode: ET.Element) -> None:
        GlobalReference.__init__(self, grefaddr, mmap)
        self._xnode = xnode

    @property
    def gaddr(self) -> str:
        return self._xnode.get("a", self.grefaddr)

    @property
    def instr(self) -> str:
        return self._xnode.get("i", "0x0")

    @property
    def faddr(self) -> str:
        return self._xnode.get("f", "0x0")

    @property
    def size(self) -> int:
        return int(self._xnode.get("s", "0"))

    @property
    def value(self) -> Optional[int]:
        optval = self._xnode.get("v")
        if optval is not None:
            return int(optval)
        else:
            return None

    def __str__(self) -> str:
        if self.grefaddr == self.gaddr:
            offset = ""
        else:
            offset = "[" + str(int(self.gaddr, 16) - int(self.grefaddr, 16)) + "]"
        if self.value is None:
            strvalue = ""
        else:
            strvalue = " (:= " + str(self.value) + ")"
        return "Store" + offset + ": " + str(self.size) + strvalue
        

class GlobalAddressArgument(GlobalReference):

    def __init__(
            self,
            grefaddr: str,
            mmap: "GlobalMemoryMap",
            xnode: ET.Element) -> None:
        GlobalReference.__init__(self, grefaddr, mmap)
        self._xnode = xnode

    @property
    def gaddr(self) -> str:
        return self._xnode.get("a", self.grefaddr)

    @property
    def iaddr(self) -> str:
        return self._xnode.get("i", "0x0")

    @property
    def faddr(self) -> str:
        return self._xnode.get("f", "0x0")

    @property
    def function(self) -> "Function":
        return self.app.function(self.faddr)

    @property
    def instr(self) -> "Instruction":
        return self.function.instruction(self.iaddr)

    @property
    def argindex(self) -> int:
        return int(self._xnode.get("aix", "-1"))

    def __str__(self) -> str:
        if self.grefaddr == self.gaddr:
            offset = ""
        else:
            offset = "[" + str(int(self.gaddr, 16) - int(self.grefaddr, 16)) + "]"
        return "Argument" + offset + ": " + str(self.instr.annotation)

                   
class GlobalLocation:

    def __init__(self, mmap: "GlobalMemoryMap", xnode: ET.Element) -> None:
        self._mmap = mmap
        self._xnode = xnode
        self._grefs: Optional[List[GlobalReference]] = None

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
    def grefs(self) -> List[GlobalReference]:
        if self._grefs is None:
            self._grefs = []
            for xgref in self._xnode.findall("gref"):
                xt = xgref.get("t", "U")
                if xt == "L":
                    gload = GlobalLoad(self.addr, self.mmap, xgref)
                    self._grefs.append(gload)
                elif xt == "S":
                    gstore = GlobalStore(self.addr, self.mmap, xgref)
                    self._grefs.append(gstore)
                elif xt == "CA":
                    garg = GlobalAddressArgument(self.addr, self.mmap, xgref)
                    self._grefs.append(garg)
                else:
                    chklogger.logger.error(
                        "Global reference type not known: %s for address %s",
                        xt, self.addr)
        return self._grefs

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
        self._undefinedlocs: Optional[Dict[str, List[GlobalReference]]] = None

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

    @property
    def undefined_locations(self) -> Dict[str, List[GlobalReference]]:
        if self._undefinedlocs is None:
            self._undefinedlocs = {}
            if self.refaddrnode is not None:
                for xundef in self.refaddrnode.findall("orphan-loc"):
                    refaddr = xundef.get("a", "0x0")
                    xlst: List[GlobalReference] = []
                    for xgref in xundef.findall("gref"):
                        xt = xgref.get("t", "U")
                        if xt == "L":
                            gload = GlobalLoad(refaddr, self, xgref)
                            xlst.append(gload)
                        elif xt == "S":
                            gstore = GlobalStore(refaddr, self, xgref)
                            xlst.append(gstore)
                        elif xt == "CA":
                            garg = GlobalAddressArgument(refaddr, self, xgref)
                            xlst.append(garg)
                        else:
                            chklogger.logger.error(
                                "Global reference type not known: %s for "
                                + "address %s",
                                xt, refaddr)
                    self._undefinedlocs[refaddr] = xlst
        return self._undefinedlocs             

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
