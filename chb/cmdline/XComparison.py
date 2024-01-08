# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs, LLC
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
"""Compare executable content of two binaries."""

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from chb.cmdline.PatchResults import PatchResults
import chb.cmdline.commandutil as UC

from chb.jsoninterface.JSONResult import JSONResult

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.elfformat.ELFSectionHeader import ELFSectionHeader


class XComparison:

    def __init__(
            self,
            is_thumb: bool,
            path1: str,
            xfile1: str,
            path2: str,
            xfile2: str,
            app1: "AppAccess",
            app2: "AppAccess",
            pdfiledata: Optional[Dict[str, Any]] = None) -> None:
        self._is_thumb = is_thumb
        self._path1 = path1
        self._path2 = path2
        self._xfile1 = xfile1
        self._xfile2 = xfile2
        self._app1 = app1
        self._app2 = app2
        self._newsections: List["ELFSectionHeader"] = []
        self._missingsections: List[str] = []
        self._sectionheaderpairs: Dict[
            str,
            Tuple[Optional["ELFSectionHeader"], Optional["ELFSectionHeader"]]] = {}
        self._switchpoints: List[str] = []
        self._newcode: List[Tuple[str, str]] = []
        self._pdfiledata = pdfiledata
        self.compare_sections()

    @property
    def is_thumb(self) -> bool:
        return self._is_thumb

    @property
    def path1(self) -> str:
        return self._path1

    @property
    def path2(self) -> str:
        return self._path2

    @property
    def xfile1(self) -> str:
        return self._xfile1

    @property
    def xfile2(self) -> str:
        return self._xfile2

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def sectionheaders1(self) -> List["ELFSectionHeader"]:
        return self.app1.header.sectionheaders

    @property
    def sectionheaders2(self) -> List["ELFSectionHeader"]:
        return self.app2.header.sectionheaders

    @property
    def newsections(self) -> List["ELFSectionHeader"]:
        return self._newsections

    @property
    def missingsections(self) -> List[str]:
        return self._missingsections

    @property
    def sectionheaderpairs(self) -> Dict[str,
            Tuple[Optional["ELFSectionHeader"], Optional["ELFSectionHeader"]]]:
        return self._sectionheaderpairs

    @property
    def switchpoints(self) -> List[str]:
        return self._switchpoints

    @property
    def pdfiledata(self) -> Optional[Dict[str, Any]]:
        return self._pdfiledata

    @property
    def trampoline_payload_addresses(self) -> List[str]:
        if self.pdfiledata is None:
            return []
        else:
            return PatchResults(self.pdfiledata).trampoline_payload_addresses

    @property
    def trampoline_addresses(self) -> List[Dict[str, str]]:
        if self.pdfiledata is None:
            return []
        else:
            return PatchResults(self.pdfiledata).trampoline_addresses

    @property
    def newcode(self) -> List[Tuple[str, str]]:
        return self._newcode

    def add_missing_section(self, name: str) -> None:
        self._missingsections.append(name)

    def add_new_section(self, s: "ELFSectionHeader") -> None:
        self._newsections.append(s)

    def set_sectionheader_pairs(
            self,
            p: Dict[
                str,
                Tuple[Optional["ELFSectionHeader"], Optional["ELFSectionHeader"]]]
    ) -> None:
        self._sectionheaderpairs = p

    def add_switchpoint(self, s: str) -> None:
        self._switchpoints.append(s)

    def add_newcode(self, start: str, endc: str) -> None:
        self._newcode.append((start, endc))

    def compare_sections(self) -> None:

        def compare_section(
                sh1: "ELFSectionHeader", sh2: "ELFSectionHeader") -> None:
            if self.is_thumb:
                if int(sh2.size, 16) > int(sh1.size, 16):
                    newvaddr = hex(int(sh1.vaddr, 16) + int(sh1.size, 16))
                    newvend = hex(int(sh1.vaddr, 16) + int(sh2.size, 16))
                    self.add_newcode(newvaddr, newvend)

        if len(self.sectionheaders1) > len(self.sectionheaders2):
            for sh1 in self.sectionheaders1:
                sh2 =self. app2.header.get_sectionheader_by_name(sh1.name)
                if sh2 is None:
                    self.add_missing_section(sh1.name)
        elif len(self.sectionheaders1) < len(self.sectionheaders2):
            for sh2 in self.sectionheaders2:
                sh1 =self.app1.header.get_sectionheader_by_name(sh2.name)
                if sh1 is None:
                    vaddr2 = sh2.vaddr
                    size2 = int(sh2.size, 16)
                    self.add_new_section(sh2)
                    if self.is_thumb:
                        self.add_switchpoint(vaddr2 + ":T")

        for sh1 in self.sectionheaders1:
            name = sh1.name
            if not name in self._sectionheaderpairs:
                sh2 = self.app2.header.get_sectionheader_by_name(name)
                self._sectionheaderpairs[name] = (sh1, sh2)
            else:
                UC.print_status_update("Duplicate section name: " + name)

        for sh2 in self.sectionheaders2:
            if not sh2.name in self._sectionheaderpairs:
                self._sectionheaderpairs[sh2.name] = (None, sh2)

        for (name, (optsh1, optsh2)) in self.sectionheaderpairs.items():
            if optsh1 is None:
                if optsh2 is not None:
                    self.add_new_section(optsh2)
            elif optsh2 is None:
                self.add_missing_section(name)
            else:
                if int(optsh2.size, 16) > int(optsh1.size, 16):
                    newvaddr = hex(int(optsh1.vaddr, 16) + int(optsh1.size, 16))
                    newvend = hex(int(optsh1.vaddr, 16) + int(optsh2.size, 16))
                    self.add_newcode(newvaddr, newvend)
                    if self.is_thumb:
                        self.add_switchpoint(newvaddr + ":T")

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["file1"] = file1 = {}
        file1["path"] = self.path1
        file1["filename"] = self.xfile1
        content["file2"] = file2 = {}
        file2["path"] = self.path2
        file2["filename"] = self.xfile2
        if len(self.newsections) > 0:
            content["newsections"] = newsecs = []
            for sh in self.newsections:
                newsec: Dict[str, str] = {}
                newsec["name"] = sh.name
                newsec["vaddr"] = sh.vaddr
                newsec["size"] = sh.size
                newsecs.append(newsec)
        if len(self.missingsections) > 0:
            content["missingsections"] = missingsecs = []
            for name in self.missingsections:
                missingsecs.append(name)
        if len(self.switchpoints) > 0:
            content["thumb-switchpoints"] = thumbswp = []
            for sw in self.switchpoints:
                thumbswp.append(sw)
        if len(self.newcode) > 0:
            content["newcode"] = nc = []
            for (s, e) in self.newcode:
                nci: Dict[str, str] = {}
                nci["startaddr"] = s
                nci["endaddr"] = e
                nc.append(nci)
        sdiffs: List[Dict[str, str]] = []
        for (name, (optsh1, optsh2)) in self.sectionheaderpairs.items():
            if optsh1 is not None and optsh2 is not None:
                if (optsh1.vaddr != optsh2.vaddr) or (optsh1.size != optsh2.size):
                    sdiff: Dict[str, str] = {}
                    sdiff["name"] = name
                    sdiff["vaddr1"] = optsh1.vaddr
                    sdiff["vaddr2"] = optsh2.vaddr
                    sdiff["size1"] = optsh1.size
                    sdiff["size2"] = optsh2.size
                    sdiffs.append(sdiff)
        if len(sdiffs) > 0:
            content["section-differences"] = sdiffs
        return JSONResult("xcomparison", content, "ok")

    def new_userdata(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if len(self.switchpoints) > 0:
            result["arm-thumb"] = self.switchpoints[:]
        trampolines = self.trampoline_addresses
        if len(trampolines) > 0:
            result["trampolines"] = trampolines
        return result

    def prepare_report(self) -> str:
        lines: List[str] = []
        for name in self.missingsections:
            lines.append(
                "  Section " + name + " is missing from the patched file")
        for sh in self.newsections:
            lines.append(
                "  Section " + sh.name + " was added to the patched file")
            lines.append(
                "    vaddr: "
                + str(sh.vaddr)
                + "; size: "
                + str(sh.size)
                + " bytes")

        if len(self.missingsections) + len(self.newsections) == 0:
            lines.append(
                "The number of sections in the original and patched file is the same")

        for (name, (optsh1, optsh2)) in self.sectionheaderpairs.items():
            if optsh1 is not None and optsh2 is not None:
                if optsh1.vaddr != optsh2.vaddr:
                    lines.append(
                        " - The starting address of section "
                        + name
                        + " changed from "
                        + optsh1.vaddr
                        + " in the original file to "
                        + optsh2.vaddr
                        + " in the patched file")
                if optsh1.size != optsh2.size:
                    lines.append(
                        " - The size of section "
                        + name
                        + " changed from "
                        + optsh1.size
                        + " in the original file to "
                        + optsh2.size
                        + " in the patched file")

        return "\n".join(lines)

    def __str__(self) -> str:
        return self.prepare_report()
