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

from typing import Any, Callable, Dict, List, Optional, Sequence

from chb.models.ModelsAccess import ModelsAccess

import chb.peformat.PESection as S
import chb.peformat.PESectionHeader as H
import chb.peformat.PEImportDirectoryEntry as E

import chb.util.fileutil as UF
import chb.util.xmlutil as UX


coff_header_attributes = [
    "machine",
    "number-of-sections",
    "size",
    "time-stamp",
    "characteristics"
    ]

optional_header_attributes = [
    "address-of-entry-point",
    "base-of-code",
    "base-of-data",
    "file-alignment",
    "image-base",
    "magic-number",
    "major-linker-version",
    "major-os-version",
    "major-subsystem-version",
    "number-of-rva-and-sizes",
    "section-alignment",
    "size-of-code",
    "size-of-headers",
    "size-of-heap-commit",
    "size-of-heap-reserve",
    "size-of-image",
    "size-of-initialized-data",
    "size-of-uninitialized-data",
    "size-of-stack-commit",
    "size-of-stack-reserve",
    "subsystem"
    ]

valuedescriptor: Dict[str, Callable[[str], str]] = {}


class PECoffFileHeader:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    def _get(self, tag: str, default: Optional[str] = None) -> str:
        xval = self.xnode.get(tag)
        if xval:
            return xval
        elif default:
            return default
        else:
            raise UF.CHBError(tag + " not found in coff header")

    def get(self, tag: str) -> str:
        if tag in coff_header_attributes:
            return self._get(tag)
        else:
            raise UF.CHBError(tag + " is not a valid coff-header element")

    @property
    def machine(self) -> str:
        return self._get("machine")

    @property
    def number_of_sections(self) -> str:
        return self._get("number-of-sections")

    @property
    def size(self) -> str:
        return self._get("size")

    @property
    def timestamp(self) -> str:
        return self._get("time-stamp")

    @property
    def file_characteristics(self) -> str:
        return self._get("characteristics")

    @property
    def file_characteristics_text(self) -> List[str]:
        xchar = self.xnode.find("file-characteristics")
        if xchar is not None:
            lines: List[str] = []
            for x in xchar.findall("charx"):
                xname = x.get("name")
                if xname:
                    lines.append((" " * 3) + xname)
                else:
                    raise UF.CHBError("Name not found in characteristics")
            return lines
        else:
            raise UF.CHBError("file-characteristics not found in coff header")


class PEOptionalHeader:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    def _get(self, tag: str, default: Optional[str] = None) -> str:
        xval = self.xnode.get(tag)
        if xval:
            return xval
        elif default:
            return default
        else:
            raise UF.CHBError(tag + " not found in optional header")

    def get(self, tag: str) -> str:
        if tag == "size-of-uninitialized-data":
            return self.size_of_uninitialized_data
        elif tag in optional_header_attributes:
            return self._get(tag)
        else:
            raise UF.CHBError(tag + " is not a valid element for optional header")

    @property
    def address_of_entry_point(self) -> str:
        return self._get("address-of-entry-point")

    @property
    def base_of_code(self) -> str:
        return self._get("base-of-code")

    @property
    def base_of_data(self) -> str:
        return self._get("base-of-data")

    @property
    def file_alignment(self) -> str:
        return self._get("file-alignment")

    @property
    def image_base(self) -> str:
        return self._get("image-base")

    @property
    def magic_number(self) -> str:
        return self._get("magic-number")

    @property
    def major_linker_version(self) -> str:
        return self._get("major-linker-version")

    @property
    def major_os_version(self) -> str:
        return self._get("major-os-version")

    @property
    def major_subsystem_version(self) -> str:
        return self._get("major-subsystem-version")

    @property
    def number_of_rva_and_sizes(self) -> str:
        return self._get("number-of-rva-and-sizes")

    @property
    def section_alignment(self) -> str:
        return self._get("section-alignment")

    @property
    def size_of_code(self) -> str:
        return self._get("size-of-code")

    @property
    def size_of_headers(self) -> str:
        return self._get("size-of-headers")

    @property
    def size_of_heap_commit(self) -> str:
        return self._get("size-of-heap-commit")

    @property
    def size_of_heap_reserve(self) -> str:
        return self._get("size-of-heap-reserve")

    @property
    def size_of_stack_reserve(self) -> str:
        return self._get("size-of-stack-reserve")

    @property
    def size_of_image(self) -> str:
        return self._get("size-of-image")

    @property
    def size_of_initialized_data(self) -> str:
        return self._get("size-of-initialized-data")

    @property
    def size_of_uninitialized_data(self) -> str:
        return self._get("size-of-uninitialized-data", default="0x0")

    @property
    def size_of_stack_commit(self) -> str:
        return self._get("size-of-stack-commit")

    @property
    def subsystem(self) -> str:
        return self._get("subsystem")


class PEHeader:
    """Main entry point to access the raw data in the executable."""

    @staticmethod
    def fmt_name() -> str:
        return "pe32"

    @staticmethod
    def get_xnode(path: str, filename: str) -> ET.Element:
        return UF.get_pe_header_xnode(path, filename)

    def __init__(
            self,
            pathname: str,
            filename: str,
            xnode: ET.Element,
            deps: Sequence[str] = []) -> None:
        self._pathname = pathname
        self._filename = filename
        self.xnode = xnode
        self._models = ModelsAccess(deps)
        self._sectionheaders: Dict[str, H.PESectionHeader] = {}
        self._importtables: Dict[str, E.PEImportDirectoryEntry] = {}
        self._sections: Dict[str, S.PESection] = {}
        self._coffheader: Optional[PECoffFileHeader] = None
        self._optionalheader: Optional[PEOptionalHeader] = None

    @property
    def pathname(self) -> str:
        return self._pathname

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def models(self) -> ModelsAccess:
        return self._models

    @property
    def section_headers(self) -> Dict[str, H.PESectionHeader]:
        if len(self._sectionheaders) == 0:
            xheaders = self.xnode.find("section-headers")
            if xheaders is not None:
                for h in xheaders.findall("section-header"):
                    header = H.PESectionHeader(self, h)
                    self._sectionheaders[header.name] = header
            else:
                raise UF.CHBError(
                    "Element section-headers not found in PE header")
        return self._sectionheaders

    @property
    def max_address_space(self) -> str:
        result = 0
        for sh in self.section_headers.values():
            vaddr = int(sh.virtual_address, 16)
            vsize = int(sh.virtual_size, 16)
            if vaddr + vsize > result:
                result = vaddr + vsize
        result += int(self.optional_header.image_base, 16)
        return hex(result)

    def is_in_address_space(self, addr: int) -> bool:
        base = int(self.optional_header.image_base, 16)
        maxaddr = int(self.max_address_space, 16)
        return addr >= base and addr < maxaddr

    @property
    def import_tables(self) -> Dict[str, E.PEImportDirectoryEntry]:
        if len(self._importtables) == 0:
            ximport = self.xnode.find("import-directory")
            if ximport:
                for i in ximport.findall("directory-entry"):
                    entry = E.PEImportDirectoryEntry(self, i)
                    self._importtables[entry.dllname] = entry
        return self._importtables

    @property
    def sections(self) -> Dict[str, S.PESection]:
        if len(self._sections) == 0:
            for x in UF.get_pe_section_xnodes(self.pathname, self.filename):
                section = S.PESection(self, x)
                self._sections[section.virtual_address] = section
        return self._sections

    def has_section(self, va: str) -> bool:
        return va in self.sections

    def get_section(self, va: str) -> S.PESection:
        if va in self.sections:
            return self.sections[va]
        else:
            raise UF.CHBError("No section found for address " + va)

    @property
    def coff_header(self) -> PECoffFileHeader:
        if self._coffheader is None:
            xcoff = self.xnode.find("coff-file-header")
            if xcoff:
                self._coffheader = PECoffFileHeader(xcoff)
            else:
                raise UF.CHBError("No coff header found in PEHeader")
        return self._coffheader

    @property
    def optional_header(self) -> PEOptionalHeader:
        if self._optionalheader is None:
            xoptional = self.xnode.find("optional-header")
            if xoptional:
                self._optionalheader = PEOptionalHeader(xoptional)
            else:
                raise UF.CHBError("No optional found in PEHeader")
        return self._optionalheader

    @property
    def machine(self) -> str:
        return self.coff_header.machine

    @property
    def number_of_sections(self) -> str:
        return self.coff_header.number_of_sections

    @property
    def optional_header_size(self) -> str:
        return self.coff_header.size

    @property
    def time_stamp(self) -> str:
        return self.coff_header.timestamp

    @property
    def file_characteristics(self) -> str:
        return self.coff_header.file_characteristics

    @property
    def address_of_entry_point(self) -> str:
        return self.optional_header.address_of_entry_point

    @property
    def base_of_code(self) -> str:
        return self.optional_header.base_of_code

    @property
    def base_of_data(self) -> str:
        return self.optional_header.base_of_data

    @property
    def file_alignment(self) -> str:
        return self.optional_header.file_alignment

    @property
    def image_base(self) -> str:
        return self.optional_header.image_base

    @property
    def magic_number(self) -> str:
        return self.optional_header.magic_number

    @property
    def major_linker_version(self) -> str:
        return self.optional_header.major_linker_version

    @property
    def major_os_version(self) -> str:
        return self.optional_header.major_os_version

    @property
    def major_subsystem_version(self) -> str:
        return self.optional_header.major_subsystem_version

    @property
    def number_of_rva_and_sizes(self) -> str:
        return self.optional_header.number_of_rva_and_sizes

    @property
    def section_alignment(self) -> str:
        return self.optional_header.section_alignment

    @property
    def size_of_code(self) -> str:
        return self.optional_header.size_of_code

    @property
    def size_of_headers(self) -> str:
        return self.optional_header.size_of_headers

    @property
    def size_of_heap_commit(self) -> str:
        return self.optional_header.size_of_heap_commit

    @property
    def size_of_heap_reserve(self) -> str:
        return self.optional_header.size_of_heap_reserve

    @property
    def size_of_image(self) -> str:
        return self.optional_header.size_of_image

    @property
    def size_of_initialized_data(self) -> str:
        return self.optional_header.size_of_initialized_data

    @property
    def size_of_uninitialized_data(self) -> str:
        return self.optional_header.size_of_uninitialized_data

    @property
    def size_of_stack_commit(self) -> str:
        return self.optional_header.size_of_stack_commit

    @property
    def size_of_stack_reserve(self) -> str:
        return self.optional_header.size_of_stack_reserve

    @property
    def subsystem(self) -> str:
        return self.optional_header.subsystem

    @property
    def file_characteristics_text(self) -> List[str]:
        return self.coff_header.file_characteristics_text

    def as_dictionary(self) -> Dict[str, Any]:
        name = self.filename
        result: Dict[str, Any] = {}
        result['name'] = name[:-5] if name.endswith('.iexe') else name[:-4]
        result['peheader'] = {}
        localetable = UF.get_locale_tables(categories=["PE"])
        coffheader = self.coff_header
        optionalheader = self.optional_header
        for p in coff_header_attributes:
            propertyvalue = coffheader.get(p)
            if p in valuedescriptor:
                propertyvalue = valuedescriptor[p](propertyvalue)
            result['peheader'][p] = resultp = {}
            resultp['value'] = propertyvalue
            resultp['heading'] = localetable['peheader'][p]
        for p in optional_header_attributes:
            propertyvalue = optionalheader.get(p)
            if p in valuedescriptor:
                propertyvalue = valuedescriptor[p](propertyvalue)
            result['peheader'][p] = resultp = {}
            resultp['value'] = propertyvalue
            resultp['heading'] = localetable['peheader'][p]
        result['peheader']['file-characteristics'] = resultfc = {}
        resultfc['value'] = ','.join(self.file_characteristics_text)
        resultfc['heading'] = 'File characteristics'
        result['import_tables'] = {}
        for tablename in self.import_tables:
            table = self.import_tables[tablename]
            result['import_tables'][table.dllname] = table.as_dictionary()
        result['section_headers'] = {}
        for h in self.section_headers:
            header = self.section_headers[h]
            result['section_headers'][header.name] = header.as_dictionary()
        return result

    def __str__(self) -> str:
        lines: List[str] = []

        def addline(tag: str, value: str) -> None:
            lines.append(tag.ljust(32) + ': ' + str(value))

        lines.append('=~' * 30)
        lines.append('PE Header for ' + self.filename)
        lines.append('-' * 60)
        addline('Machine', self.machine)
        addline('Number of sections', self.number_of_sections)
        addline('Size of optional header', self.optional_header_size)
        addline('Time/date', self.time_stamp)
        addline('Characteristics', self.file_characteristics)
        lines.append(' ')
        lines.extend(self.file_characteristics_text)
        lines.append(' ')
        addline('Magic number', self.magic_number)
        addline('Major linker version', self.major_linker_version)
        addline('Size of code', self.size_of_code)
        addline('Size of initialized data', self.size_of_initialized_data)
        addline('Size of uninitialized data', self.size_of_uninitialized_data)
        addline('Address of entry point', self.address_of_entry_point)
        addline('Base of code', self.base_of_code)
        addline('Base of data', self.base_of_data)
        addline('Image base', self.image_base)
        addline('Section alignment', self.section_alignment)
        addline('File alignment', self.file_alignment)
        addline('Major Operating System version', self.major_os_version)
        addline('Major Subsystem version', self.major_subsystem_version)
        addline('Size of image', self.size_of_image)
        addline('Size of headers', self.size_of_headers)
        addline('Subsystem', self.subsystem)
        lines.append(' ')
        addline('Size of stack reserve', self.size_of_stack_reserve)
        addline('Size of stack commit', self.size_of_stack_commit)
        addline('Size of heap reserve', self.size_of_heap_reserve)
        addline('Size of heap commit', self.size_of_heap_commit)
        addline('Number of rva and sizes', self.number_of_rva_and_sizes)
        lines.append('-' * 60)
        return '\n'.join(lines)
