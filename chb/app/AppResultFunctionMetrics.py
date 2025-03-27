# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2025 Aarno Labs LLC
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

from typing import Dict, List, Optional, TYPE_CHECKING

import chb.util.fileutil as UF


class AppResultFunctionMetrics:
    """Analysis metrics for a single assembly function."""

    def __init__(
            self, xnode: ET.Element):
        self.xnode = xnode
        self._faddr: Optional[str] = None
        self._metrics: Optional[ET.Element] = None
        self._xprec: Optional[ET.Element] = None
        self._xmemacc: Optional[ET.Element] = None
        self._xcfg: Optional[ET.Element] = None
        self._xcalls: Optional[ET.Element] = None

    @property
    def faddr(self) -> str:
        if self._faddr is None:
            self._faddr = self.xnode.get("a")
            if self._faddr is None:
                raise UF.CHBError("Function address is missing")
        return self._faddr

    @property
    def metrics(self) -> ET.Element:
        if self._metrics is None:
            self._metrics = self.xnode.find("fmetrics")
            if self._metrics is None:
                raise UF.CHBError("Fmetrics missing in function"
                                  + self.faddr)
        return self._metrics

    @property
    def time(self) -> float:
        t = self.xnode.get("time")
        if t is not None:
            return float(t)
        else:
            raise UF.CHBError("Time is missing in function " + self.faddr)

    @property
    def xprec(self) -> ET.Element:
        if self._xprec is None:
            self._xprec = self.metrics.find("prec")
            if self._xprec is None:
                raise UF.CHBError("Precision metrics missing in function "
                                  + self.faddr)
        return self._xprec

    @property
    def espp(self) -> float:
        r = self.xprec.get("esp")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Esp precision is missing for " + self.faddr)

    @property
    def readsp(self) -> float:
        r = self.xprec.get("reads")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Reads precision is missing for " + self.faddr)

    @property
    def writesp(self) -> float:
        r = self.xprec.get("writes")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Writes precision is missing for " + self.faddr)

    @property
    def xmemacc(self) -> ET.Element:
        if self._xmemacc is None:
            self._xmemacc = self.metrics.find("memacc")
            if self._xmemacc is None:
                raise UF.CHBError("Memory access element is missing for "
                                  + self.faddr)
        return self._xmemacc

    @property
    def memreads(self) -> int:
        return int(self.xmemacc.get("reads", "0"))

    @property
    def memwrites(self) -> int:
        return int(self.xmemacc.get("writes", "0"))

    @property
    def xcfg(self) -> ET.Element:
        if self._xcfg is None:
            self._xcfg = self.metrics.find("cfg")
            if self._xcfg is None:
                raise UF.CHBError("Cfg element is missing for function "
                                  + self.faddr)
        return self._xcfg

    @property
    def instruction_count(self) -> int:
        return int(self.xcfg.get("instrs", "0"))

    @property
    def block_count(self) -> int:
        return int(self.xcfg.get("bblocks", "0"))

    @property
    def loop_count(self) -> int:
        return int(self.xcfg.get("loops", "0"))

    @property
    def loop_depth(self) -> int:
        return int(self.xcfg.get("loopdepth", "0"))

    @property
    def complexity(self) -> str:
        r = self.xcfg.get("cfgc")
        if r is not None:
            return r
        else:
            raise UF.CHBError("Cfg complexity is missing from " + self.faddr)

    @property
    def vcomplexity(self) -> float:
        r = self.xcfg.get("vc-complexity")
        if r is not None:
            return float(r)
        else:
            raise UF.CHBError("Variable complexity is missing from "
                              + self.faddr)

    @property
    def xcalls(self) -> ET.Element:
        if self._xcalls is None:
            self._xcalls = self.metrics.find("calls")
            if self._xcalls is None:
                raise UF.CHBError("Calls are missing from " + self.faddr)
        return self._xcalls

    @property
    def call_count(self) -> int:
        return int(self.xcalls.get("count", "0"))

    @property
    def dll_call_count(self) -> int:
        return int(self.xcalls.get("dll", "0"))

    @property
    def app_call_count(self) -> int:
        return int(self.xcalls.get("app", "0"))

    @property
    def unresolved_call_count(self) -> int:
        return int(self.xcalls.get("unr", "0"))

    @property
    def inlined_call_count(self) -> int:
        return int(self.xcalls.get("inlined", "0"))

    @property
    def static_dll_call_count(self) -> int:
        return int(self.xcalls.get("staticdll", "0"))

    @property
    def variable_count(self) -> int:
        xvars = self.metrics.find("vars")
        if xvars is not None:
            return int(xvars.get("count", "0"))
        else:
            raise UF.CHBError("Variable element is missing from " + self.faddr)

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname is not None:
            return xname
        else:
            raise UF.CHBError("Function " + self.faddr + " does not have a name")

    def has_name(self) -> bool:
        return "name" in self.xnode.attrib

    def as_dictionary(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        result['faddr'] = self.faddr
        result['time'] = str(self.time)
        result['espp'] = str(self.espp)
        result['readsp'] = str(self.readsp)
        result['writesp'] = str(self.writesp)
        result['instrs'] = str(self.instruction_count)
        result['blocks'] = str(self.block_count)
        result['complexity'] = self.complexity
        result['callcount'] = str(self.call_count)
        result['dllcallcount'] = str(self.dll_call_count)
        result['appcallcount'] = str(self.app_call_count)
        result['unrcallcount'] = str(self.unresolved_call_count)
        if self.has_name():
            result['name'] = self.name
        result['hasname'] = str(self.has_name())
        return result

    def metrics_to_string(
            self,
            shownocallees: bool = False,
            space: str = "   ",
            annotations: List[str] = []) -> str:
        callcount = ''
        name = ''
        unrc = ''
        anns = ""
        if shownocallees and (not self.has_name()):
            if self.call_count == 0:
                callcount = ' (no callees)'
        if self.has_name():
            name = ' (' + self.name + ')'
        if self.unresolved_call_count > 0:
            unrc = str(self.unresolved_call_count)
        if len(annotations) > 0:
            anns = " [" + ", ".join(annotations) + "]"

        return (str(self.faddr).ljust(10) + space
                + '{:6.1f}'.format(self.espp) + space
                + '{:6.1f}'.format(self.readsp) + space
                + '{:6.1f}'.format(self.writesp) + space
                + unrc.rjust(6) + space
                + str(self.block_count).rjust(6) + space
                + str(self.instruction_count).rjust(6) + space
                + '{:8.3f}'.format(self.time) + name + callcount + anns)
