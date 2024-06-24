# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs, LLC
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

from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.elfformat.ELFProgramHeader import ELFProgramHeader
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
        self._newsegments: List["ELFProgramHeader"] = []
        self._missingsections: List[str] = []
        self._missingsegments: List[int] = []
        self._sectionheaderpairs: Dict[
            str,
            Tuple[Optional["ELFSectionHeader"],
                  Optional["ELFSectionHeader"]]] = {}
        self._programheaderpairs: Dict[
            int,
            Tuple[Optional["ELFProgramHeader"],
                  Optional["ELFProgramHeader"]]] = {}
        self._switchpoints: List[str] = []
        self._newcode: List[Tuple[str, str]] = []
        self._pdfiledata = pdfiledata
        self._messages: List[str] = []

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
    def messages(self) -> List[str]:
        return self._messages

    @property
    def programheaders1(self) -> List["ELFProgramHeader"]:
        return self.app1.header.programheaders

    @property
    def programheaders2(self) -> List["ELFProgramHeader"]:
        return self.app2.header.programheaders

    @property
    def newsegments(self) -> List["ELFProgramHeader"]:
        return self._newsegments

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
    def missingsegments(self) -> List[int]:
        return self._missingsegments

    @property
    def sectionheaderpairs(self) -> Dict[
            str,
            Tuple[Optional["ELFSectionHeader"], Optional["ELFSectionHeader"]]]:
        return self._sectionheaderpairs

    @property
    def programheaderpairs(self) -> Dict[
            int,
            Tuple[Optional["ELFProgramHeader"], Optional["ELFProgramHeader"]]]:
        return self._programheaderpairs

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

    def add_missing_segment(self, index: int) -> None:
        self._missingsegments.append(index)

    def add_new_section(self, s: "ELFSectionHeader") -> None:
        self._newsections.append(s)

    def add_new_segment(self, s: "ELFProgramHeader") -> None:
        self._newsegments.append(s)

    def set_sectionheader_pairs(
            self,
            p: Dict[
                str,
                Tuple[Optional["ELFSectionHeader"],
                      Optional["ELFSectionHeader"]]]
    ) -> None:
        self._sectionheaderpairs = p

    def add_switchpoint(self, s: str) -> None:
        self._switchpoints.append(s)

    def add_newcode(self, start: str, endc: str) -> None:
        self._newcode.append((start, endc))

    def compare_segments(self) -> None:
        for ph1 in self.programheaders1:
            index = ph1.index
            if not index in self._programheaderpairs:
                ph2 = self.app2.header.get_programheader_by_index(index)
                self._programheaderpairs[index] = (ph1, ph2)
            else:
                chklogger.logger.warning("Duplicate header index: %d", index)

        for ph2 in self.programheaders2:
            index = ph2.index
            if not index in self._programheaderpairs:
                self._programheaderpairs[index] = (None, ph2)

        for (index, (optph1, optph2)) in self.programheaderpairs.items():
            if optph1 is None:
                if optph2 is not None:
                    self.add_new_segment(optph2)
            elif optph2 is None:
                self.add_missing_segment(optph1.index)
            else:
                if optph1.has_memsize() and optph2.has_memsize():
                    size1 = int(optph1.memsize, 16)
                    size2 = int(optph2.memsize, 16)
                    if size1 != size2:
                        self._messages.append(
                            (f"Segment {index} size changed from "
                             + f"{size1} to {size2}"))

    def compare_sections(self) -> None:

        for sh1 in self.sectionheaders1:
            name = sh1.name
            if not name in self._sectionheaderpairs:
                sh2 = self.app2.header.get_sectionheader_by_name(name)
                self._sectionheaderpairs[name] = (sh1, sh2)
            else:
                chklogger.logger.warning("Duplicate section name: " + name)

        for sh2 in self.sectionheaders2:
            if not sh2.name in self._sectionheaderpairs:
                self._sectionheaderpairs[sh2.name] = (None, sh2)

        for (name, (optsh1, optsh2)) in self.sectionheaderpairs.items():
            if optsh1 is None:
                if optsh2 is not None:
                    self.add_new_section(optsh2)
                    vaddr2 = optsh2.vaddr
                    if self.is_thumb:
                        self.add_switchpoint(vaddr2 + ":T")
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
        if len(self.newsegments) > 0:
            content["newsegments"] = newsegs = []
            for ph in self.newsegments:
                newseg: Dict[str, str] ={}
                newseg["index"] = str(ph.index)
                if ph.has_virtual_address():
                    newseg["vaddr"] = ph.virtual_address
                if ph.has_memsize():
                    newseg["size"] = ph.memsize
                newsegs.append(newseg)
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
        if len(self.newsegments) > 0 and len(self.newsections) == 0:
            sectionheaders: Dict[str, Dict[str, str]] = {}
            for (index, (ph1, ph2)) in self.programheaderpairs.items():
                if ph1 is None and ph2 is not None:
                    seg: Dict[str, str] = {}
                    if ph2.has_virtual_address():
                        seg["addr"] = ph2.virtual_address
                    if ph2.has_memsize():
                        seg["size"] = ph2.memsize
                    seg["offset"] = ph2.get_default_property_value(
                        "p_offset", "0x0")
                    seg["type"] = ph2.get_default_property_value(
                        "p_type", "0x1")
                    seg["flags"] = ph2.get_default_property_value(
                        "p_flags", "0x7")
                    seg["status"] = "new"
                    sectionheaders["segment_" + str(ph2.index)] = seg
            result["section-headers"] = sectionheaders
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

        for ph in self.newsegments:
            lines.append(
                "  A new segment ("
                + str(ph.index)
                + ") was added to the patched file: ")
            lines.append(str(ph))
            lines.append("")

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
