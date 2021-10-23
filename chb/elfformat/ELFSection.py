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

from typing import Any, cast, Dict, List, TYPE_CHECKING, Union

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    import chb.elfformat.ELFDictionary
    import chb.elfformat.ELFHeader
    import chb.elfformat.ELFSectionHeader


symbolbindings = {
    0: 'LOCAL',
    1: 'GLOBAL',
    2: 'WEAK'
    }


def get_symbol_binding_desc(i: int) -> str:
    if i in symbolbindings:
        return symbolbindings[i]
    else:
        return str(i)


symboltypes = {
    0: 'NOTYPE',
    1: 'OBJECT',
    2: 'FUNC',
    3: 'SECTION',
    4: 'FILE'
    }


def get_symbol_type_desc(i: int) -> str:
    if i in symboltypes:
        return symboltypes[i]
    else:
        return str(i)


dynamicarraytags = {
    0: 'DT_NULL',
    1: 'DT_NEEDED',
    2: 'DT_PLTRELSZ',
    3: 'DT_PLTGOT',
    4: 'DT_HASH',
    5: 'DT_STRTAB',
    6: 'DT_SYMTAB',
    7: 'DT_RELA',
    8: 'DT_RELASZ',
    9: 'DT_RELAENT',
    10: 'DT_STRSZ',
    11: 'DT_SYMENT',
    12: 'DT_INIT',
    13: 'DT_FINI',
    14: 'DT_SONAME',
    15: 'DT_RPATH',
    16: 'DT_SYMBOLIC',
    17: 'DT_REL',
    18: 'DT_RELSZ',
    19: 'DT_RELENT',
    20: 'DT_PLTREL',
    21: 'DT_DEBUG',
    22: 'DT_TEXTREL',
    23: 'DT_JMPREL'
    }


def get_dynamic_array_tag_name(i: int) -> str:
    if i in dynamicarraytags:
        return dynamicarraytags[i]
    else:
        return str(i)


class ELFSection:

    def __init__(self,
                 elfheader: "chb.elfformat.ELFHeader.ELFHeader",
                 sectionheader: "chb.elfformat.ELFSectionHeader.ELFSectionHeader",
                 xnode: ET.Element) -> None:
        self.elfheader = elfheader
        self.sectionheader = sectionheader
        self.xnode = xnode
        self._values: Dict[int, int] = {}     # address -> value

    @property
    def name(self) -> str:
        return self.sectionheader.name

    @property
    def hexdata(self) -> ET.Element:
        xdata = self.xnode.find("hex-data")
        if xdata is not None:
            return xdata
        else:
            raise UF.CHBError("Hex-data missing from ELF section "
                              + self.name)

    @property
    def data(self) -> ET.Element:
        xdata = self.xnode.find("data")
        if xdata is not None:
            return xdata
        else:
            raise UF.CHBError("Data element missing from ELF section "
                              + self.name)

    @property
    def values(self) -> Dict[int, int]:
        if len(self._values) == 0:
            for ablock in self.hexdata.findall("ablock"):
                for hexline in ablock.findall("aline"):
                    xaddr = hexline.get("va")
                    xbytes = hexline.get("bytes")
                    if xaddr and xbytes:
                        bytestring = xbytes.replace(" ", "")
                        for i in range(0, len(bytestring), 2):
                            byteval = bytestring[i: i+2]
                            addr = int(xaddr, 16)
                            self._values[addr + (i // 2)] = int(byteval, 16)
                    else:
                        if xaddr is None:
                            raise UF.CHBError("Address missing from section line")
                        if xbytes is None:
                            raise UF.CHBError("Bytes missing from section line")
        return self._values

    def has_address(self, addr: int) -> bool:
        return addr in self.values

    def get_byte_value(self, address: int) -> int:
        if address in self.values:
            return self.values[address]
        else:
            raise UF.CHBError("Address not found in section " + self.name)

    def get_word_value(self, address: int, little_endian=True) -> int:
        if address in self.values:
            b1 = self.get_byte_value(address)
            b2 = self.get_byte_value(address + 1)
            if little_endian:
                return (b2 << 8) + b1
            else:
                return (b1 << 8) + b2
        else:
            raise UF.CHBError("Word address not found in section " + self.name)

    def get_doubleword_value(self, address: int, little_endian=True) -> int:
        if address in self.values:
            b1 = self.get_byte_value(address)
            b2 = self.get_byte_value(address + 1)
            b3 = self.get_byte_value(address + 2)
            b4 = self.get_byte_value(address + 3)
            if little_endian:
                return b1 + (b2 << 8) + (b3 << 16) + (b4 << 24)
            else:
                return b4 + (b3 << 8) + (b2 << 16) + (b1 << 24)
        else:
            raise UF.CHBError("DWord address not found in section " + self.name)

    def get_string(self, addr: int) -> str:
        b = self.get_byte_value(addr)
        result = ''
        while b:
            result += chr(b)
            addr += 1
            b = self.get_byte_value(addr)
        return result

    def get_linked_stringtable(self) -> "ELFSection":
        shlink = int(self.sectionheader.linked_section, 16)
        return self.elfheader.get_string_table(shlink)

    def as_dictionary(self) -> Dict[Any, Any]:
        return {}


class ELFStringTable(ELFSection):

    def __init__(
            self,
            elfheader: "chb.elfformat.ELFHeader.ELFHeader",
            sectionheader: "chb.elfformat.ELFSectionHeader.ELFSectionHeader",
            xnode: ET.Element) -> None:
        ELFSection.__init__(self, elfheader, sectionheader, xnode)
        self._strings: Dict[int, str] = {}

    @property
    def strings(self) -> Dict[int, str]:
        if len(self._strings) == 0:
            table = self.data.find("string-table")
            if table:
                for c in table.findall("str"):
                    xpos = c.get("p")
                    xstr = c.get("s")
                    if xpos and xstr:
                        self._strings[int(xpos)] = xstr
                    else:
                        if xpos is None:
                            raise UF.CHBError(
                                "Position is missing from string table")
                        if xstr is None:
                            raise UF.CHBError(
                                "String is missing from string table")
            else:
                raise UF.CHBError("String table missing from string table section")
        return self._strings

    def get_string(self, position: int) -> str:
        if position < 0:
            raise UF.CHBError("Invalid position for string: " + str(position))
        if position == 0:
            return ""
        if position in self.strings:
            return self.strings[position]
        else:
            prev = 0
            for p in sorted(self.strings):
                if position < p:
                    return self.strings[prev][(position-prev):]
        raise UF.CHBError("Index out of bounds in get_string: " + str(position))

    def as_dictionary(self) -> Dict[int, str]:
        return self.strings

    def __str__(self) -> str:
        lines: List[str] = []
        for p in sorted(self.strings):
            lines.append(str(p).rjust(4) + ' : ' + str(self.strings[p]))
        return '\n'.join(lines)


class ELFSymbol:
    """Representation of a symbol.

    rep-record representation:
    tags: 0: st_name (hex-string)
          1: st_value (hex-string)
          2: st_size (hex-string)
    args: 0: name (string-index)
          1: st_info
          2: st_other
          3: st_shndx
    """

    def __init__(
            self,
            symboltable: "ELFSymbolTable",
            xnode: ET.Element) -> None:
        self.symboltable = symboltable
        self.stringtable = self.symboltable.stringtable
        self.xnode = xnode
        self.dictionary = self.symboltable.elfheader.dictionary
        rep = IT.get_rep(xnode, indextag="id")
        self.id = rep[0]
        self.tags = rep[1]
        self.args = rep[2]

    @property
    def value(self) -> str:
        return self.tags[1]

    @property
    def st_name(self) -> str:
        return self.dictionary.get_string(int(self.args[0]))

    @property
    def st_info(self) -> int:
        return self.args[1]

    @property
    def st_bind(self) -> str:
        # st_bind = st_info >> 4
        return get_symbol_binding_desc(self.st_info >> 4)

    @property
    def st_type(self) -> str:
        # st_type = st_info & 15
        return get_symbol_type_desc(self.st_info & 15)

    @property
    def section_index(self) -> int:
        return self.args[3]

    @property
    def st_size(self) -> int:
        return int(self.tags[2], 16)

    @property
    def is_exported(self) -> bool:
        return (
            self.section_index > 0
            and self.st_type == "FUNC"
            and self.st_bind == "GLOBAL")

    def as_dictionary(self) -> Dict[str, Union[str, int]]:
        result: Dict[str, Union[str, int]] = {}
        result['name'] = self.st_name
        result['value'] = self.tags[1]
        result['binding'] = self.st_bind
        result['type'] = self.st_type
        result['size'] = self.st_size
        result['section'] = self.section_index
        return result

    def __str__(self) -> str:
        d = self.as_dictionary()
        lines: List[str] = []
        for k in sorted(d):
            lines.append('  ' + str(k).rjust(10) + ': ' + str(d[k]))
        return '\n'.join(lines)


class ELFSymbolTable(ELFSection):

    def __init__(
            self,
            elfheader: "chb.elfformat.ELFHeader.ELFHeader",
            sectionheader: "chb.elfformat.ELFSectionHeader.ELFSectionHeader",
            xnode: ET.Element) -> None:
        ELFSection.__init__(self, elfheader, sectionheader, xnode)
        self._symbols: Dict[int, ELFSymbol] = {}
        self.stringtable = self.get_linked_stringtable()

    @property
    def symbols(self) -> Dict[int, ELFSymbol]:
        if len(self._symbols) == 0:
            xtable = self.data.find("symbol-table")
            if xtable:
                for r in xtable.findall("n"):
                    xid = r.get("id")
                    if xid:
                        self._symbols[int(xid)] = ELFSymbol(self, r)
                    else:
                        raise UF.CHBError("Symbol record without id")
            else:
                raise UF.CHBError("Symbol table not found in section "
                                  + self.name)
        return self._symbols

    def as_dictionary(self) -> Dict[int, Any]:
        result: Dict[int, Any] = {}
        for i in self.symbols:
            result[i] = self.symbols[i].as_dictionary()
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for i in self.symbols:
            lines.append('Symbol ' + str(i))
            lines.append(str(self.symbols[i]))
        return '\n'.join(lines)


class ELFRelocationEntry:
    """Representation of a relocation entry.

    rep-record representation:
    tags: 0: r_offset (hex-string)
          1: r_info  (hex-string)
          2: symbol-value (hex-string)
    args: 0: type (r_info & 255)
          1: name (string-index)   (optional, sometimes missing)
    """

    def __init__(
            self,
            relocationtable: "ELFRelocationTable",
            xnode: ET.Element):
        self.relocationtable = relocationtable
        self.xnode = xnode
        rep = IT.get_rep(xnode, indextag='id')
        self._id = rep[0]
        self.tags = rep[1]
        self.args = rep[2]

    @property
    def id(self) -> int:
        return self._id

    @property
    def dictionary(self) -> "chb.elfformat.ELFDictionary.ELFDictionary":
        return self.relocationtable.elfheader.dictionary

    def has_symbol_name(self) -> bool:
        return len(self.args) > 1

    @property
    def symbol_name(self) -> str:
        if len(self.args) > 1:
            return self.dictionary.get_string(self.args[1])
        else:
            raise UF.CHBError(
                "Relocation entry does not have an associated symbol name")

    @property
    def symbol_type(self) -> int:
        return self.args[0]

    @property
    def symbol_value(self) -> str:
        return self.tags[2]

    @property
    def r_offset(self) -> str:
        return self.tags[0]

    def as_dictionary(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        result['symbolname'] = self.symbol_name if self.has_symbol_name() else "?"
        result['offset'] = self.r_offset
        return result

    def __str__(self) -> str:
        if self.has_symbol_name():
            return (self.r_offset + ": " + self.symbol_name)
        else:
            return self.r_offset + ": _"


class ELFRelocationTable(ELFSection):

    def __init__(
            self,
            elfheader: "chb.elfformat.ELFHeader.ELFHeader",
            sectionheader: "chb.elfformat.ELFSectionHeader.ELFSectionHeader",
            xnode: ET.Element) -> None:
        ELFSection.__init__(self, elfheader, sectionheader, xnode)
        self._entries: List[ELFRelocationEntry] = []

    @property
    def entries(self) -> List[ELFRelocationEntry]:
        if len(self._entries) == 0:
            xtable = self.data.find("relocation-table")
            if xtable:
                for r in xtable.findall("n"):
                    self._entries.append(ELFRelocationEntry(self, r))
        return self._entries

    def as_dictionary(self) -> Dict[int, Any]:
        result: Dict[int, Any] = {}
        for entry in self.entries:
            result[entry.id] = entry.as_dictionary()
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for e in sorted(self.entries, key=lambda x: x.r_offset):
            lines.append(str(e))
        return '\n'.join(lines)


class ELFDynamicEntry:
    """Represents an entry in the dynamic table."""

    def __init__(
            self,
            dynamictable: "ELFDynamicTable",
            xnode: ET.Element) -> None:
        self.dynamictable = dynamictable
        self.xnode = xnode
        self.rep = IT.get_rep(xnode, indextag='id')
        self._id = self.rep[0]
        self.tags = self.rep[1]
        self._d_tag = self.tags[0]
        self._d_un = self.tags[1]

    @property
    def id(self) -> int:
        return self._id

    @property
    def d_tag(self) -> str:
        return self._d_tag

    @property
    def d_un(self) -> str:
        return self._d_un

    @property
    def tag_name(self) -> str:
        return self.d_tag

    @property
    def value(self) -> str:
        if self.tag_name == 'DT_PLTREL':
            if self.d_un == '0x11':
                return 'DT_REL'
            elif self.d_un == '0x7':
                return 'DT_RELA'
            else:
                return self.d_un
        return self.d_un

    def as_dictionary(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        result['tag'] = self.d_tag
        result['value'] = self.value
        return result

    def __str__(self) -> str:
        return (self.tag_name.ljust(10) + ': ' + str(self.value))


class ELFDynamicTable(ELFSection):

    def __init__(
            self,
            elfheader: "chb.elfformat.ELFHeader.ELFHeader",
            sectionheader: "chb.elfformat.ELFSectionHeader.ELFSectionHeader",
            xnode: ET.Element) -> None:
        ELFSection.__init__(self, elfheader, sectionheader, xnode)
        self._entries: List[ELFDynamicEntry] = []

    @property
    def entries(self) -> List[ELFDynamicEntry]:
        if len(self._entries) == 0:
            xtable = self.data.find("dynamic-table")
            if xtable:
                for r in xtable.findall("n"):
                    self._entries.append(ELFDynamicEntry(self, r))
        return self._entries

    @property
    def dynamic_libraries(self) -> List[str]:
        """List of dynamically linked libraries."""

        result: List[str] = []
        stringtable = cast(ELFStringTable, self.get_linked_stringtable())
        for e in self.entries:
            if e.tag_name == "DT_NEEDED":
                strpos = int(e.value)
                result.append(stringtable.get_string(strpos))
        return result

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for (i, entry) in enumerate(self.entries):
            result[str(i)] = entry.as_dictionary()
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for e in self.entries:
            lines.append(str(e))
        return '\n'.join(lines)
