# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2026 Aarno Labs LLC
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
"""Information about a function carried across analysis rounds."""

import xml.etree.ElementTree as ET

from typing import Dict, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.api.AppSummary import AppSummary
from chb.api.CallTarget import CallTarget
from chb.api.CallTargetInfo import CallTargetInfo
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.api.FormatStringSpec import FormatStringSpec
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.BDictionary import BDictionary


class FunctionInfo:

    def __init__(
            self,
            bd: "BDictionary",
            ixd: "InterfaceDictionary",
            faddr: str,
            xnode: ET.Element) -> None:
        self._bd = bd
        self._ixd = ixd
        self._faddr = faddr
        self.xnode = xnode
        self._calltargets: Dict[str, CallTarget] = {}
        self._variablenames: Dict[int, str] = {}
        self._calltargetinfos: Dict[str, CallTargetInfo] = {}
        self._formatstringspecs: Optional[Dict[str, Tuple[str,FormatStringSpec]]] = None

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def bd(self) -> "BDictionary":
        return self._bd

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self._ixd

    @property
    def appsummary(self) -> Optional[AppSummary]:
        xsummary = self.xnode.find("summary")
        if xsummary is not None:
            xfintf = xsummary.get("fintf")
            xfsem = xsummary.get("fsem")
            xfsig = xsummary.get("fsig")
            if xfintf is not None and xfsem is not None and xfsig is not None:
                appsignature = self.ixd.function_signature(int(xfsig))
                appfinterface = self.ixd.function_interface(int(xfintf))
                appfsemantics = self.ixd.function_semantics(int(xfsem))
                return AppSummary(appsignature, appfinterface, appfsemantics)
        return None

    @property
    def calltargets(self) -> Mapping[str, CallTarget]:
        if len(self._calltargets) == 0:
            ctnode = self.xnode.find("call-targets")
            if ctnode is not None:
                for ctinfo in ctnode.findall("ctinfo"):
                    xaddr = ctinfo.get("a")
                    if xaddr is not None:
                        self._calltargets[xaddr] = (
                            self.ixd.read_xml_call_target(ctinfo))
                    else:
                        raise UF.CHBError("Ctinfo node without address")
            vnnode = self.xnode.find("variable-names")
            if vnnode is not None:
                for xn in vnnode.findall("n"):
                    vix = xn.get("vix")
                    vname = xn.get("name")
                    if vix is not None and vname is not None:
                        self._variablenames[int(vix)] = vname
                    else:
                        raise UF.CHBError("Index or name missing from variablename")
        return self._calltargets

    @property
    def calltargetinfos(self) -> Mapping[str, CallTargetInfo]:
        if len(self._calltargetinfos) == 0:
            ctnode = self.xnode.find("call-targets")
            if ctnode is not None:
                for ctinfo in ctnode.findall("ctinfo"):
                    xaddr = ctinfo.get("a")
                    if xaddr is not None:
                        ctgt = self.ixd.read_xml_call_target(ctinfo)
                        fintf = self.ixd.read_xml_function_interface(ctinfo)
                        fsem = self.ixd.read_xml_function_semantics(ctinfo)
                        self._calltargetinfos[xaddr] = CallTargetInfo(
                            ctgt, fintf, fsem)
        return self._calltargetinfos

    @property
    def formatstrings(self) -> Mapping[str, Tuple[str, "FormatStringSpec"]]:
        if self._formatstringspecs is None:
            self._formatstringspecs = {}
            fsnode = self.xnode.find("format-strings")
            if fsnode is not None:
                for fs in fsnode.findall("fs"):
                    xaddr = fs.get("a")
                    ixs = int(fs.get("ixs", "-1"))
                    ixc = int(fs.get("ixc", "-1"))
                    kind = fs.get("kind", "printf")
                    if xaddr is not None and ixs > 0 and ixc > 0:
                        formatstring = self.bd.string(ixs)
                        formatspec = self.ixd.formatstring_spec(ixc)
                        self._formatstringspecs[xaddr] = (formatstring, formatspec)
        return self._formatstringspecs

    @property
    def lhs_names(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for (iaddr, ctinfo) in self.calltargetinfos.items():
            result[iaddr] = "rtn_" + ctinfo.calltarget.name
        return result

    @property
    def variablenames(self) -> Mapping[int, str]:
        if len(self._variablenames) == 0:
            vnnode = self.xnode.find("variable-names")
            if vnnode is not None:
                for xn in vnnode.findall("n"):
                    vix = xn.get("vix")
                    vname = xn.get("name")
                    if vix is not None and vname is not None:
                        self._variablenames[int(vix)] = vname
                    else:
                        raise UF.CHBError(
                            "Index or name missing from variablename")
        return self._variablenames

    def call_target_info(self, callsite: str) -> CallTargetInfo:
        if self.has_call_target_info(callsite):
            return self.calltargetinfos[callsite]
        else:
            raise UF.CHBError(
                f"Function at {self.faddr} does not have a call target at "
                f"{callsite}")

    def has_call_target_info(self, callsite: str) -> bool:
        return callsite in self.calltargetinfos

    def call_target(self, callsite: str) -> CallTarget:
        if self.has_call_target(callsite):
            return self.calltargets[callsite]
        else:
            raise UF.CHBError(
                "Function at "
                + self.faddr
                + "does not have a call target at "
                + callsite)

    def has_call_target(self, callsite: str) -> bool:
        return callsite in self.calltargets

    def has_variable_name(self, index: int) -> bool:
        return index in self.variablenames

    def variable_name(self, index: int) -> str:
        if index in self.variablenames:
            return self.variablenames[index]
        else:
            raise UF.CHBError("Index " + str(index) + " not found in variable names")
