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

from typing import Any, Callable, cast, Dict, List, Optional, Sequence, Tuple

from chb.elfformat.ELFProgramHeader import ELFProgramHeader
from chb.elfformat.ELFSectionHeader import ELFSectionHeader
from chb.elfformat.ELFSection import ELFSection
from chb.elfformat.ELFSection import ELFStringTable
from chb.elfformat.ELFSection import ELFSymbolTable
from chb.elfformat.ELFSection import ELFRelocationTable
from chb.elfformat.ELFSection import ELFDynamicTable
from chb.elfformat.ELFDictionary import ELFDictionary

import chb.util.fileutil as UF


fileheader_attributes = [
    "e_machine",
    "e_type",
    "e_ehsize",
    "e_entry",
    "e_phentsize",
    "e_phnum",
    "e_phoff",
    "e_shentsize",
    "e_shnum",
    "e_shoff",
    "e_shstrndx",
    "e_version"
    ]

objectfileheader_attributes = [
    "e_machine",
    "e_type",
    "e_ehsize",
    "e_phentsize",
    "e_phnum",
    "e_shentsize",
    "e_shnum",
    "e_shoff",
    "e_shstrndx",
    "e_version"
    ]

machines = {
    "0": "No machine",
    "1": "AT&T WE 32100",
    "2": "SPARC",
    "3": "Intel 80386",
    "4": "Motorola 68000",
    "5": "Motorola 88000",
    "7": "Intel 80860",
    "8": "MIPS RS3000"
    }

filetypes = {
    "0": "No file type",
    "1": "Relocatable file",
    "2": "Executable file",
    "3": "Shared object file",
    "4": "Core file",
    "0xff00": "Processor-specific",
    "0xffff": "Processor-specific"
    }

versions = {
    "0x0": "Invalid version",
    "0x1": "Current version"
    }


def get_value(d: Dict[str, str], v: str) -> str:
    if v in d:
        return d[v]
    else:
        return v


valuedescriptor: Dict[str, Callable[[str], str]] = {
    "e_machine": lambda v: get_value(machines, v),
    "e_type": lambda v: get_value(filetypes, v),
    "e_ehsize": lambda v: str(v) + " (bytes)",
    "e_phentsize": lambda v: str(v) + " (bytes)",
    "e_shentsize": lambda v: str(v) + " (bytes)",
    "e_phoff": lambda v: str(v) + " (bytes into file)",
    "e_shoff": lambda v: str(v) + " (bytes into file)",
    "e_version": lambda v: get_value(versions, v)
    }


class ELFHeader:

    @staticmethod
    def fmt_name() -> str:
        return "elf"

    @staticmethod
    def get_xnode(path: str, filename: str) -> ET.Element:
        return UF.get_elf_header_xnode(path, filename)

    def __init__(
            self,
            pathname: str,
            filename: str,
            xnode: ET.Element,
            # ignored, used for compatibility with PEHeader
            deps: Sequence[str] = []) -> None:
        self._pathname = pathname
        self._filename = filename
        self.xnode = xnode
        self._dictionary: Optional[ELFDictionary] = None
        self._programheaders: List[ELFProgramHeader] = []
        self._sectionheaders: List[ELFSectionHeader] = []
        self._sections: Dict[int, ELFSection] = {}

    def _get_default_attribute(self, tag: str, default: str) -> str:
        xprop = self.xnode.get(tag)
        if xprop:
            return xprop
        else:
            return default

    @property
    def pathname(self) -> str:
        return self._pathname

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def dictionary(self) -> ELFDictionary:
        if self._dictionary is None:
            xdictionary = UF.get_elf_dictionary_xnode(
                self.pathname, self.filename)
            self._dictionary = ELFDictionary()
            self._dictionary.initialize(xdictionary)
        return self._dictionary

    @property
    def xfile_header(self) -> ET.Element:
        xheader = self.xnode.find("elf-file-header")
        if xheader is not None:
            return xheader
        else:
            raise UF.CHBError("File header not found in ELFHeader")

    @property
    def programheaders(self) -> List[ELFProgramHeader]:
        if len(self._programheaders) == 0:
            xheaders = self.xnode.find("elf-program-headers")
            if xheaders:
                for h in xheaders.findall("program-header"):
                    self._programheaders.append(ELFProgramHeader(self, h))
            else:
                raise UF.CHBError("Elf-program-headers element not found")
        return self._programheaders

    @property
    def sectionheaders(self) -> List[ELFSectionHeader]:
        if len(self._sectionheaders) == 0:
            xheaders = self.xnode.find("elf-section-headers")
            if xheaders:
                for h in xheaders.findall("section-header"):
                    self._sectionheaders.append(ELFSectionHeader(self, h))
            else:
                raise UF.CHBError("Elf-section-headers element not found")
        return self._sectionheaders

    @property
    def image_base(self) -> str:
        result = 0xffffffff
        for ph in self.programheaders:
            if ph.has_virtual_address():
                hexvaddr = ph.virtual_address
                vaddr = int(hexvaddr, 16)
                if vaddr < result:
                    result = vaddr
        return hex(result)

    @property
    def is_big_endian(self) -> bool:
        return self._get_default_attribute("endian", "little") == "big"

    def e_machine(self) -> str:
        xmachine = self.xfile_header.get("e-machine")
        if xmachine:
            return xmachine
        else:
            raise UF.CHBError("E-machine attribute not found in ELFHeader")

    def e_type(self) -> int:
        etype = self.xfile_header.get("e_type")
        if etype:
            return int(etype)
        else:
            raise UF.CHBError("E-type attribute not found in ELFHeader")

    def is_object_file(self) -> bool:
        return self.e_type() == 1

    def has_string_table(self) -> bool:
        return any([s.is_string_table for s in self.sectionheaders])

    def has_symbol_table(self) -> bool:
        return any([s.is_symbol_table for s in self.sectionheaders])

    def has_dynamic_symbol_table(self) -> bool:
        return any([s.is_dynamic_symbol_table for s in self.sectionheaders])

    def has_dynamic_table(self) -> bool:
        return any([s.is_dynamic_table for s in self.sectionheaders])

    def get_string_table_indices(self) -> List[int]:      # there can be multiple
        result: List[int] = []
        for (i, h) in enumerate(self.sectionheaders):
            if h.is_string_table:
                result.append(i)
        return result

    def get_symbol_table_index(self) -> int:       # there is only one
        for (i, h) in enumerate(self.sectionheaders):
            if h.is_symbol_table:
                return i
        return -1

    def get_dynamic_symbol_table_index(self) -> int:     # there is only one
        for (i, h) in enumerate(self.sectionheaders):
            if h.is_dynamic_symbol_table:
                return i
        return -1

    def get_dynamic_table_index(self) -> int:      # there is only one
        for (i, h) in enumerate(self.sectionheaders):
            if h.is_dynamic_table:
                return i
        return -1

    def get_string_table(self, index: int) -> ELFSection:
        if index in self._sections:
            return self._sections[index]
        else:
            sectionx = UF.get_elf_section_xnode(
                self.pathname, self.filename, str(index))
            self._sections[index] = ELFStringTable(
                self, self.sectionheaders[index], sectionx)
            return self._sections[index]

    def get_string_tables(self) -> List[ELFSection]:
        indices = self.get_string_table_indices()
        result: List[ELFSection] = []
        for index in indices:
            if index in self._sections:
                result.append(self._sections[index])
            else:
                sectionx = UF.get_elf_section_xnode(
                    self.pathname, self.filename, str(index))
                self._sections[index] = ELFStringTable(
                    self, self.sectionheaders[index], sectionx)
                result.append(self._sections[index])
        return result

    @property
    def sections(self) -> Dict[int, ELFSection]:
        for (index, h) in enumerate(self.sectionheaders):
            if index in self._sections:
                continue
            xsection = UF.get_elf_section_xnode(
                self.pathname, self.filename, str(index))
            if h.is_dynamic_table:
                self._sections[index] = ELFDynamicTable(
                    self, self.sectionheaders[index], xsection)
            elif h.is_string_table:
                self._sections[index] = ELFStringTable(
                    self, self.sectionheaders[index], xsection)
            elif h.is_dynamic_symbol_table or h.is_symbol_table:
                self._sections[index] = ELFSymbolTable(
                    self, self.sectionheaders[index], xsection)
            else:
                self._sections[index] = ELFSection(
                    self, self.sectionheaders[index], xsection)
        return self._sections

    def get_sectionheader_by_name(self, name: str) -> Optional[ELFSectionHeader]:
        for h in self.sectionheaders:
            if h.name == name:
                return h
        else:
            return None

    def get_section_start_address(self, name: str) -> Optional[str]:
        h = self.get_sectionheader_by_name(name)
        if h is not None:
            return h.vaddr
        else:
            return None

    def get_memory_value(self, index: int, addr: int) -> int:
        if index in self.sections:
            return self.sections[index].get_byte_value(addr)
        else:
            raise UF.CHBError("Section " + str(index) + " not found")

    def get_word_value(self, index: int, addr: int, little_endian: bool = True) -> int:
        if index in self.sections:
            return self.sections[index].get_word_value(addr, little_endian)
        else:
            raise UF.CHBError("Section " + str(index) + " not found")

    def get_doubleword_value(self, index: int, addr: int, little_endian: bool = True) -> int:
        if index in self.sections:
            return self.sections[index].get_doubleword_value(addr, little_endian)
        else:
            raise UF.CHBError("Section " + str(index) + " not found")

    def get_string(self, index: int, addr: int) -> str:
        if index in self.sections:
            return self.sections[index].get_string(addr)
        else:
            raise UF.CHBError("Section " + str(index) + " not found")

    def get_elf_section_index(self, addr: int) -> Optional[int]:
        for h in self.sectionheaders:
            if h.is_initialized:
                vaddr = int(h.vaddr, 16)
                size = int(h.size, 16)
                if addr >= vaddr and addr < vaddr + size:
                    return int(h.index)
        return None

    @property
    def max_address_space(self) -> str:
        result = 0
        for ph in self.programheaders:
            if ph.has_virtual_address() and ph.has_memsize():
                vaddr = int(ph.virtual_address, 16)
                memsize = int(ph.memsize, 16)
                if vaddr + memsize > result:
                    result = vaddr + memsize
        return hex(result)

    def is_in_address_space(self, addr: int) -> bool:
        base = int(self.image_base, 16)
        maxaddr = int(self.max_address_space, 16)
        return addr >= base and addr < maxaddr

    def is_in_elf_section(self, addr: int) -> bool:
        index = self.get_elf_section_index(addr)
        return index is not None and self.sectionheaders[index].is_address_in_section(addr)

    def get_symbol_table(self) -> ELFSection:
        index = self.get_symbol_table_index()
        if index in self.sections:
            return self.sections[index]
        else:
            xsection = UF.get_elf_section_xnode(
                self.pathname, self.filename, str(index))
            self.sections[index] = ELFSymbolTable(
                self, self.sectionheaders[index], xsection)
            return self.sections[index]

    def get_dynamic_symbol_table(self) -> ELFSection:
        index = self.get_dynamic_symbol_table_index()
        if index in self.sections:
            return self.sections[index]
        else:
            xsection = UF.get_elf_section_xnode(
                self.pathname, self.filename, str(index))
            self.sections[index] = ELFSymbolTable(
                self, self.sectionheaders[index], xsection)
            return self.sections[index]

    def get_relocation_tables(self) -> List[Tuple[ELFSectionHeader, ELFSection]]:
        result: List[Tuple[ELFSectionHeader, ELFSection]] = []
        for sh in self.sectionheaders:
            if sh.is_relocation_table:
                if sh.index not in self.sections:
                    xsection = UF.get_elf_section_xnode(
                        self.pathname, self.filename, sh.index)
                    index = int(sh.index)
                    self._sections[index] = ELFRelocationTable(
                        self, self.sectionheaders[index], xsection)
                result.append((sh, self.sections[index]))
        return result

    def get_dynamic_table(self) -> ELFDynamicTable:
        index = self.get_dynamic_table_index()
        if index in self.sections:
            return cast(ELFDynamicTable, self.sections[index])
        else:
            xsection = UF.get_elf_section_xnode(
                self.pathname, self.filename, str(index))
            self.sections[index] = ELFDynamicTable(
                self, self.sectionheaders[index], xsection)
            return cast(ELFDynamicTable, self.sections[index])

    def as_dictionary(self) -> Dict[str, Any]:
        # note: update for multiple string tables
        #       add relocation tables
        try:
            result: Dict[str, Any] = {}
            result["name"] = self.filename
            result["fileheader"] = {}
            result["programheaders"] = []
            result["sectionheaders"] = []
            fileheader = self.xfile_header
            localetable = UF.get_locale_tables(categories=["ELF"])
            attributes = fileheader_attributes
            if self.is_object_file():
                attributes = objectfileheader_attributes
            for p in attributes:
                propvalue = fileheader.get(p)
                if propvalue is None:
                    print("Property " + p + " not found in file-header")
                if p in valuedescriptor and propvalue is not None:
                    propertyvalue = valuedescriptor[p](propvalue)
                elif propvalue is not None:
                    propertyvalue = propvalue
                else:
                    propertyvalue = "unspecified"
                result["fileheader"][p] = {}
                result["fileheader"][p]["value"] = propertyvalue
                result["fileheader"][p]["heading"] = localetable["elfheader"][p]
            if not self.is_object_file():
                for ph in self.programheaders:
                    result["programheaders"].append(ph.as_dictionary())
            for s in self.sectionheaders:
                result["sectionheaders"].append(s.as_dictionary())
            if self.has_string_table():
                result["stringtables"] = {}
                for ss in self.get_string_tables():
                    result["stringtables"][ss.name] = s.as_dictionary()
            if self.has_symbol_table():
                result["symboltable"] = self.get_symbol_table().as_dictionary()
            if self.has_dynamic_symbol_table():
                dynsymtable = self.get_dynamic_symbol_table()
                result["dynamicsymboltable"] = dynsymtable.as_dictionary()
            if self.has_dynamic_table():
                result["dynamictable"] = self.get_dynamic_table().as_dictionary()
            return result
        except KeyError as e:
            raise UF.CHBError("KeyError in ELFHeader: " + str(e))

    def section_layout_to_string(self) -> str:
        lines: List[str] = []
        lines.append("\nSection Layout\n")
        lines.append(
            "index".ljust(8)
            + "name".ljust(16)
            + "start".rjust(10)
            + "size".rjust(10)
            + "   "
            + "flags")
        lines.append("-" * 80)
        for s in sorted(self.sectionheaders, key=lambda s: int(s.index)):
            lines.append(
                str(s.index).rjust(3)
                + "     "
                + s.name.ljust(16)
                + s.vaddr.rjust(10)
                + s.size.rjust(10)
                + "   "
                + s.flags_string)
        return "\n".join(lines)

    def fileheaderstr(self) -> str:
        d = self.as_dictionary()
        lines: List[str] = []
        for k in d["fileheader"]:
            lines.append(
                str(d["fileheader"][k]["heading"]).ljust(35)
                + ": "
                + str(d["fileheader"][k]["value"]))

        if self.has_dynamic_table():
            lines.append("\nLinked Libraries")
            dynamictable = self.get_dynamic_table()
            for s in dynamictable.dynamic_libraries:
                lines.append("   " + s)
        return "\n".join(lines)

    def __str__(self) -> str:
        d = self.as_dictionary()
        lines: List[str] = []
        lines.append(self.fileheaderstr())
        lines.append("\nProgram Headers")
        lines.append("-" * 80)
        if not self.is_object_file():
            for p in self.programheaders:
                lines.append("Program header " + str(p.index))
                lines.append(str(p))
                lines.append(" ")
        for s in sorted(self.sectionheaders, key=lambda s: s.index):
            lines.append("Section header " + str(s.index) + " (" + str(s.name) + ")")
            lines.append(str(s))
            lines.append(" ")
        if self.has_string_table():
            for ss in self.get_string_tables():
                lines.append("\nString table: " + ss.name)
                lines.append(str(ss))
        if self.has_symbol_table():
            symtab = self.get_symbol_table()
            lines.append("\nSymbol Table")
            lines.append("-- linked string table section: "
                         + str(int(symtab.sectionheader.linked_section, 16)))
            lines.append(str(symtab))
        if self.has_dynamic_symbol_table():
            symtab = self.get_dynamic_symbol_table()
            lines.append("\nDynamic Symbol Table")
            lines.append("-- linked string table section: "
                         + str(int(symtab.sectionheader.linked_section, 16)))
            lines.append(str(symtab))
        for (sh, section) in self.get_relocation_tables():
            lines.append("\nRelocation Table "
                         + str(sh.index)
                         + " ("
                         + str(sh.name)
                         + ")")
            lines.append("-- linked symbol table section: "
                         + str(int(sh.linked_section, 16)))
            lines.append(str(section))
        if self.has_dynamic_table():
            table = self.get_dynamic_table()
            lines.append("\nDynamic Table")
            lines.append("-- linked string table section: "
                         + str(int(table.sectionheader.linked_section, 16)))
            lines.append(str(self.get_dynamic_table()))
        lines.append(self.section_layout_to_string())
        return "\n".join(lines)
