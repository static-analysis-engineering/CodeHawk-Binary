# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
    import chb.elfformat.ELFHeader

programheader_attributes = [
    "p_type",
    "p_offset",
    "p_vaddr",
    "p_paddr",
    "p_filesz",
    "p_memsz",
    "p_flags",
    "p_align"
    ]

programheader_types = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR"
    }


def get_program_header_type(i: int) -> str:
    if i in programheader_types:
        return programheader_types[i]
    else:
        return str(hex(i))


programheaderflags = {
    0: 'X',
    1: 'R',
    2: 'W'
    }


def get_program_header_flag(i: int) -> str:
    if i in programheaderflags:
        return programheaderflags[i]
    else:
        return '?'


def get_program_header_flags(flags: str) -> str:
    binstring = bin(int(flags, 16))[2:].zfill(32)
    result = ''
    for (i, c) in enumerate(str(binstring)):
        if c == "0":
            continue
        result += ' ' + get_program_header_flag(31-i)
    return result


class ELFProgramHeader:

    def __init__(
            self,
            elfheader: "chb.elfformat.ELFHeader.ELFHeader",
            xnode: ET.Element) -> None:
        self.elfheader = elfheader
        self.xnode = xnode

    @property
    def index(self) -> int:
        xindex = self.xnode.get("index")
        if xindex:
            return int(xindex)
        else:
            raise UF.CHBError("Index not found in program header")

    @property
    def virtual_address(self) -> str:
        xva = self.xnode.get("p_vaddr")
        if xva:
            return xva
        else:
            raise UF.CHBError("Virtual address not found in program header")

    def get_default_property_value(self, tag: str, default: str) -> str:
        xprop = self.xnode.get(tag)
        if xprop:
            return xprop
        else:
            return default

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["index"] = self.index
        localetable = UF.get_locale_tables(tables=[("ELF", "elfprogramheader")])
        for p in programheader_attributes:
            propertyvalue = self.get_default_property_value(p, "0x0")
            if p == "p_type":
                propertyvalue = get_program_header_type(int(propertyvalue, 16))
            if p == "p_flags":
                propertyvalue += " (" + get_program_header_flags(propertyvalue) + ")"
            result[p] = {}
            result[p]["value"] = propertyvalue
            result[p]["heading"] = localetable["elfprogramheader"][p]
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        d = self.as_dictionary()
        for k in sorted(d):
            if k == "index":
                continue
            lines.append(str(d[k]["heading"]).ljust(18) + ": " + str(d[k]["value"]))
        return "\n".join(lines)
