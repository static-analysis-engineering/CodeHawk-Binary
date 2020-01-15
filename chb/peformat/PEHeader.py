# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

import chb.util.fileutil as UF
import chb.util.xmlutil  as UX

from chb.peformat.PESection import PESection
from chb.peformat.PESectionHeader import PESectionHeader
from chb.peformat.PEImportDirectoryEntry import PEImportDirectoryEntry

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

valuedescriptor = {}

class PEHeader():
    '''Main entry point to access the raw data in the executable'''

    def __init__(self,app,xnode):
        self.app = app
        self.xnode = xnode
        self.sectionheaders = {}      # section name -> PESectionHeader
        self.importtables = {}        # dll name -> PEImportDirectoryEntry
        self.sections = {}            # virtual address -> PESection

    def get_path_name(self): return self.app.path

    def get_filename(self): return self.app.filename

    def get_section_headers(self):
        self._get_section_headers()
        return self.sectionheaders.values()

    def get_import_tables(self):
        self._get_import_tables()
        return self.importtables.values()

    def get_sections(self):
        self._get_sections()
        return self.sections.values()

    def get_section(self,va):
        self._get_sections()
        if va in self.sections: return self.sections[va]
        for va in self.sections: print(va)

    def get_coff_header(self): 
        return self.xnode.find('coff-file-header')

    def get_machine(self): 
        return self.get_coff_header().get('machine')

    def get_number_of_sections(self): 
        return self.get_coff_header().get('number-of-sections')

    def get_optional_header_size(self): 
        return self.get_coff_header().get('size')

    def get_time_stamp(self): 
        return self.get_coff_header().get('time-stamp')

    def get_file_characteristics(self): 
        return self.get_coff_header().get('characteristics')

    def get_optional_header(self): 
        return self.xnode.find('optional-header')

    def get_address_of_entry_point(self):
        return self.get_optional_header().get('address-of-entry-point')

    def get_base_of_code(self):
        return self.get_optional_header().get('base-of-code')

    def get_base_of_data(self):
        return self.get_optional_header().get('base-of-data')

    def get_file_alignment(self):
        return self.get_optional_header().get('file-alignment')

    def get_image_base(self):
        return self.get_optional_header().get('image-base')

    def get_magic_number(self):
        return self.get_optional_header().get('magic-number')

    def get_major_linker_version(self):
        return self.get_optional_header().get('major-linker-version')

    def get_major_os_version(self):
        return self.get_optional_header().get('major-os-version')

    def get_major_subsystem_version(self):
        return self.get_optional_header().get('major-subsystem-version')

    def get_number_of_rva_and_sizes(self):
        return self.get_optional_header().get('number-of-rva-and-sizes')

    def get_section_alignment(self):
        return self.get_optional_header().get('section-alignment')

    def get_size_of_code(self):
        return self.get_optional_header().get('size-of-code')

    def get_size_of_headers(self):
        return self.get_optional_header().get('size-of-headers')

    def get_size_of_heap_commit(self):
        return self.get_optional_header().get('size-of-heap-commit')

    def get_size_of_heap_reserve(self):
        return self.get_optional_header().get('size-of-heap-reserve')

    def get_size_of_image(self):
        return self.get_optional_header().get('size-of-image')

    def get_size_of_initialized_data(self):
        return self.get_optional_header().get('size-of-initialized-data')

    def get_size_of_uninitialized_data(self):
        return self.get_optional_header().get('size-of-uninitialized-data','0x0')

    def get_size_of_stack_commit(self):
        return self.get_optional_header().get('size-of-stack-commit')

    def get_size_of_stack_reserve(self):
        return self.get_optional_header().get('size-of-stack-reserve')

    def get_subsystem(self):
        return self.get_optional_header().get('subsystem')

    def str_file_characteristics(self):
        lines = []
        for x in self.get_coff_header().find('file-characteristics').findall('charx'):
            lines.append((' ' * 3) + x.get('name'))
        return lines

    def as_dictionary(self):
        name = self.get_filename()
        result = {}
        result['name'] = name[:-5] if name.endswith('.iexe') else name[:-4] 
        result['peheader'] = {}
        localetable = UF.get_locale_tables(categories=["PE"])
        coffheader = self.get_coff_header()
        optionalheader = self.get_optional_header()
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
        resultfc['value'] = ','.join(self.str_file_characteristics())
        resultfc['heading'] = 'File characteristics'
        result['import_tables'] = {}
        for table in self.get_import_tables():
            result['import_tables'][table.dllname] = table.as_dictionary()
        result['section_headers'] = {}
        for header in self.get_section_headers():
            result['section_headers'][header.name] = header.as_dictionary()
        return result

    def __str__(self):
        lines = []
        def addline(tag,value):
            lines.append(tag.ljust(32) + ': ' +  str(value))
        lines.append('=~' * 30)
        lines.append('PE Header for ' + self.get_filename())
        lines.append('-' * 60)
        addline('Machine', self.get_machine())
        addline('Number of sections', self.get_number_of_sections())
        addline('Size of optional header', self.get_optional_header_size())
        addline('Time/date', self.get_time_stamp())
        addline('Characteristics', self.get_file_characteristics())
        lines.append(' ')
        lines.extend(self.str_file_characteristics())
        lines.append(' ')
        addline('Magic number',self.get_magic_number())
        addline('Major linker version', self.get_major_linker_version())
        addline('Size of code', self.get_size_of_code())
        addline('Size of initialized data', self.get_size_of_initialized_data())
        addline('Size of uninitialized data', self.get_size_of_uninitialized_data())
        addline('Address of entry point', self.get_address_of_entry_point())
        addline('Base of code', self.get_base_of_code())
        addline('Base of data', self.get_base_of_data())
        addline('Image base', self.get_image_base())
        addline('Section alignment', self.get_section_alignment())
        addline('File alignment', self.get_file_alignment())
        addline('Major Operating System version', self.get_major_os_version())
        addline('Major Subsystem version', self.get_major_subsystem_version())
        addline('Size of image', self.get_size_of_image())
        addline('Size of headers', self.get_size_of_headers())
        addline('Subsystem', self.get_subsystem())
        lines.append(' ')
        addline('Size of stack reserve', self.get_size_of_stack_reserve())
        addline('Size of stack commit', self.get_size_of_stack_commit())
        addline('Size of heap reserve', self.get_size_of_heap_reserve())
        addline('Size of heap commit', self.get_size_of_heap_commit())
        addline('Number of rva and sizes', self.get_number_of_rva_and_sizes())
        lines.append('-' * 60)
        return '\n'.join(lines)

    def _get_section_headers(self):
        if len(self.sectionheaders) == 0:
            for h in self.xnode.find('section-headers').findall('section-header'):
                header = PESectionHeader(self,h)
                self.sectionheaders[header.name] = header

    def _get_import_tables(self):
        if len(self.importtables) == 0:
            for i in self.xnode.find('import-directory').findall('directory-entry'):
                entry = PEImportDirectoryEntry(self,i)
                self.importtables[entry.dllname] = entry

    def _get_sections(self):
        if len(self.sections) == 0:
            for x in UF.get_pe_section_xnodes(self.get_path_name(), self.get_filename()):
                section = PESection(self,x)
                self.sections[section.get_virtual_address()] = section
                
