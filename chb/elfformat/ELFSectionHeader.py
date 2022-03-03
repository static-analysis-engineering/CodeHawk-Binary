# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs LLC
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

sectionheader_attributes = [
    "sh_type",
    "sh_name",
    "sh_flags",
    "sh_addr",
    "sh_offset",
    "sh_size",
    "sh_info",
    "sh_link",
    "sh_addralign",
    "sh_entsize"
    ]

sectionheadertypes = {
    "0x0": "SHT_NullSection",
    "0x1": "SHT_ProgBits",
    "0x2": "SHT_SymTab",
    "0x3": "SHT_StrTab",
    "0x4": "SHT_Rela",
    "0x5": "SHT_Hash",
    "0x6": "SHT_Dynamic",
    "0x7": "SHT_Note",
    "0x8": "SHT_NoBits",
    "0x9": "SHT_Rel",
    "0xa": "SHT_ShLib",
    "0xb": "SHT_DynSym",
    "0xe": "SHT_InitArray",
    "0xf": "SHT_FiniArray",
    "0x10": "SHT_PreinitArray",
    "0x11": "SHT_Group",
    "0x12": "SHT_SymTabShndx"
    }


def get_section_header_type(s: str) -> str:
    if s in sectionheadertypes:
        return sectionheadertypes[s]
    else:
        return s


sectionheaderflags = {
    0: "WRITE",
    1: "ALLOC",
    2: "EXECINSTR",
    4: "MERGE",
    5: "STRINGS",
    6: "INFO_LINK",
    7: "LINK_ORDER",
    8: "OS_NONCONFORMING",
    9: "GROUP",
    10: "TLS",
    11: "COMPRESSED",
    28: "VLE (PowerPC)"
    }


def get_section_header_flag(i: int) -> str:
    if i in sectionheaderflags:
        return sectionheaderflags[i]
    else:
        return "?"


def get_section_header_flags(flags: str) -> str:
    binstring = bin(int(flags, 16))[2:].zfill(32)
    result = ""
    for (i, c) in enumerate(str(binstring)):
        if c == "0":
            continue
        result += " " + get_section_header_flag(31-i)
    return result


class ELFSectionHeader:

    def __init__(self,
                 elfheader: "chb.elfformat.ELFHeader.ELFHeader",
                 xnode: ET.Element):
        self.elfheader = elfheader
        self.xnode = xnode

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname is not None:
            return xname
        else:
            raise UF.CHBError("Name not found in section header")

    @property
    def index(self) -> str:
        xindex = self.xnode.get("index")
        if xindex:
            return xindex
        else:
            raise UF.CHBError("Index not found in section header")

    def get_default_attribute_value(self, tag: str, default: str) -> str:
        xprop = self.xnode.get(tag)
        if xprop:
            return xprop
        else:
            return default

    def attribute_values(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        result["index"] = self.index
        result["name"] = self.name
        for p in sectionheader_attributes:
            result[p] = self.get_default_attribute_value(p, "0x0")
        return result

    @property
    def section_header_type(self) -> str:
        shtype = self.get_default_attribute_value("sh_type", "0x0")
        return get_section_header_type(shtype)

    @property
    def vaddr(self) -> str:
        return self.get_default_attribute_value("sh_addr", "0x0")

    @property
    def size(self) -> str:
        return self.get_default_attribute_value("sh_size", "0x0")

    @property
    def flags_string(self) -> str:
        shflags = self.get_default_attribute_value("sh_flags", "0x0")
        return get_section_header_flags(shflags)

    @property
    def linked_section(self) -> str:
        return self.get_default_attribute_value("sh_link", "0x0")

    @property
    def is_string_table(self) -> bool:
        return self.section_header_type == "SHT_StrTab"

    @property
    def is_symbol_table(self) -> bool:
        return self.section_header_type == "SHT_SymTab"

    @property
    def is_dynamic_symbol_table(self) -> bool:
        return self.section_header_type == "SHT_DynSym"

    @property
    def is_relocation_table(self) -> bool:
        return self.section_header_type == "SHT_Rel"

    @property
    def is_dynamic_table(self) -> bool:
        return self.section_header_type == "SHT_Dynamic"

    @property
    def is_initialized(self) -> bool:
        return not(self.section_header_type == "SHT_NoBits")

    def is_address_in_section(self, addr: int):
        if self.section_header_type == "SHT_ProgBits":
            vaddr_i = int(self.vaddr, 16)
            eaddr_i = vaddr_i + int(self.size, 16)
            return addr >= vaddr_i and addr < eaddr_i
        else:
            return False

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["index"] = self.index
        result["name"] = self.name
        localetable = UF.get_locale_tables(tables=[("ELF", "elfsectionheader")])
        for p in sectionheader_attributes:
            propertyvalue = self.get_default_attribute_value(p, "0x0")
            if p == "sh_type":
                propertyvalue = get_section_header_type(propertyvalue)
            if p == "sh_flags":
                flags = get_section_header_flags(propertyvalue)
                if len(flags) > 0:
                    propertyvalue += " (" + str(flags) + ")"
            result[p] = {}
            result[p]["value"] = propertyvalue
            result[p]["heading"] = localetable["elfsectionheader"][p]
        return result

    def __str__(self) -> str:
        d = self.as_dictionary()
        lines: List[str] = []
        for k in sorted(d):
            if k == "index":
                continue
            if k == "name":
                continue
            lines.append(str(d[k]["heading"]).ljust(18) + ": " + str(d[k]["value"]))
        return "\n".join(lines)
