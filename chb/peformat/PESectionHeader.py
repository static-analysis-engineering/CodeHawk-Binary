# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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

from typing import Any, Dict, List, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.Instruction
    import chb.peformat.PEHeader

section_header_attributes = [
    "characteristics",
    "number-of-line-numbers",
    "number-of-relocations",
    "pointer-to-raw-data",
    "size-of-raw-data",
    "virtual-address",
    "virtual-size"
    ]


class PESectionHeader:
    '''Represents the header data of a single section in the executable.'''

    def __init__(
            self,
            peheader: "chb.peformat.PEHeader.PEHeader",
            xnode: ET.Element) -> None:
        self.peheader = peheader
        self.xnode = xnode

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname:
            return xname
        else:
            raise UF.CHBError("Name is missing from PESectionHeader")

    @property
    def characteristics(self) -> str:
        xchars = self.xnode.get("characteristics")
        if xchars:
            return xchars
        else:
            raise UF.CHBError("Characteristics are missing from PESectionHeader")

    @property
    def number_of_line_numbers(self) -> str:
        xlines = self.xnode.get("number-of-line-numbers")
        if xlines:
            return xlines
        else:
            raise UF.CHBError(
                "Number-of-line-numbers is missing from PESectionHeader")

    @property
    def number_of_relocations(self) -> str:
        xreloc = self.xnode.get("number-of-relocations")
        if xreloc:
            return xreloc
        else:
            raise UF.CHBError(
                "Number-of-relocations is missing from PESectionHeader")

    @property
    def pointer_to_raw_data(self) -> str:
        xptr = self.xnode.get("pointer-to-raw-data")
        if xptr:
            return xptr
        else:
            raise UF.CHBError(
                "Pointer-to-raw-data is missing from PESectionHeader")

    @property
    def pointer_to_relocations(self) -> str:
        xptr = self.xnode.get("pointer-to-relocations")
        if xptr:
            return xptr
        else:
            raise UF.CHBError(
                "Pointer to relocations is missing from PESectionHeader")

    @property
    def size_of_raw_data(self) -> str:
        xsize = self.xnode.get("size-of-raw-data")
        if xsize:
            return xsize
        else:
            raise UF.CHBError(
                "Size of raw data is missing from PESectionHeader")

    @property
    def virtual_address(self) -> str:
        xva = self.xnode.get("virtual-address")
        if xva:
            return xva
        else:
            raise UF.CHBError("Virtual address is missing from PESectionHeader")

    @property
    def virtual_size(self) -> str:
        xsize = self.xnode.get("virtual-size")
        if xsize:
            return xsize
        else:
            raise UF.CHBError("Virtual size is missing from PESectionHeader")

    @property
    def characteristics_text(self) -> List[str]:
        lines: List[str] = []
        xcharx = self.xnode.find("section-charxs")
        if xcharx:
            for x in xcharx.findall("charx"):
                xname = x.get("name")
                if xname:
                    lines.append((" " * 3) + xname)
                else:
                    raise UF.CHBError("Name missing from characteristics text")
        else:
            raise UF.CHBError(
                "Section-characteristics text missing from PESectionHeader")
        return lines

    @property
    def is_executable(self) -> bool:
        xcharx = self.xnode.find("section-charxs")
        if xcharx:
            for x in xcharx.findall("charx"):
                xname = x.get("name")
                if xname:
                    if xname == "IMAGE_SCN_MEM_EXECUTE":
                        return True
                else:
                    raise UF.CHBError("Name missing from characteristics text")
            else:
                return False
        else:
            raise UF.CHBError(
                "Section-characteristics text missing from PESectionHeader")

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["name"] = self.name
        localetable = UF.get_locale_tables(tables=[("PE", "pesectionheader")])
        for p in section_header_attributes:
            propertyvalue = self.xnode.get(p, "0x0")
            result[p] = {}
            result[p]["value"] = propertyvalue
            result[p]["heading"] = localetable["pesectionheader"][p]
        result["section-characterists"] = sectionxs = {}
        sectionxs["value"] = ",".join(self.characteristics_text)
        sectionxs["heading"] = "Section characteristics"
        return result

    def __str__(self) -> str:
        lines: List[str] = []

        def addline(tag: str, value: str) -> None:
            lines.append((" " * 3) + tag.ljust(32) + ": " + str(value))

        lines.append("-" * 60)
        lines.append("Section header for " + self.name)
        lines.append("-" * 60)
        addline("Name", self.name)
        addline("Virtual size", self.virtual_size)
        addline("Virtual address", self.virtual_address)
        addline("Size of raw data", self.size_of_raw_data)
        addline("Pointer to raw data", self.pointer_to_raw_data)
        addline("Pointer to relocations", self.pointer_to_relocations)
        addline("Number of line numbers", self.number_of_line_numbers)
        addline("Number of relocations", self.number_of_relocations)
        addline("Characteristics", self.characteristics)
        lines.append(" ")
        lines.extend(self.characteristics_text)
        lines.append("-" * 60)
        return "\n".join(lines)
