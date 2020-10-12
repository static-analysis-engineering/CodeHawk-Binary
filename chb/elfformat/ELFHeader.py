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
from chb.elfformat.ELFProgramHeader import ELFProgramHeader
from chb.elfformat.ELFSectionHeader import ELFSectionHeader
from chb.elfformat.ELFSection import ELFSection
from chb.elfformat.ELFSection import ELFStringTable
from chb.elfformat.ELFSection import ELFSymbolTable
from chb.elfformat.ELFSection import ELFRelocationTable
from chb.elfformat.ELFSection import ELFDynamicTable
from chb.elfformat.ELFDictionary import ELFDictionary

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

def get_value(d,v):
    if v in d:
        return d[v]
    else:
        return v

valuedescriptor = {
    "e_machine": lambda v: get_value(machines,v),
    "e_type": lambda v: get_value(filetypes,v),
    "e_ehsize": lambda v: str(v) + " (bytes)",
    "e_phentsize": lambda v: str(v) + " (bytes)",
    "e_shentsize": lambda v: str(v) + " (bytes)",
    "e_phoff": lambda v: str(v) + " (bytes into file)",
    "e_shoff": lambda v: str(v) + " (bytes into file)",
    "e_version": lambda v: get_value(versions,v)
    }
    

class ELFHeader():

    def __init__(self,app,xnode):
        self.app = app
        self.xnode = xnode
        self.dictionary = ELFDictionary()
        self.programheaders = []
        self.sectionheaders = []
        self.sections = {}
        self._initialize()

    def get_file_header(self):
        return self.xnode.find('elf-file-header')

    def get_image_base(self):
        result = 0xffffffff
        for ph in self.programheaders:
            vaddr = ph.get_virtual_address()
            if vaddr:
                vaddr = int(vaddr,16)
                if vaddr < result:
                    result = vaddr
        return hex(result)

    def is_big_endian(self):
        return self.xnode.get('endian','little') == 'big'

    def get_e_machine(self):
        return self.get_file_header().get('e-machine')

    def has_string_table(self):
        return any( [ s.is_string_table() for s in self.sectionheaders ])

    def has_symbol_table(self):
        return any( [ s.is_symbol_table() for s in self.sectionheaders ])

    def has_dynamic_symbol_table(self):
        return any( [ s.is_dynamic_symbol_table() for s in self.sectionheaders ])

    def has_dynamic_table(self):
        return any( [ s.is_dynamic_table() for s in self.sectionheaders ])

    def get_string_table_indices(self):      # there can be multiple
        result = []
        for (i,h) in enumerate(self.sectionheaders):
            if h.is_string_table(): result.append(i)
        return result

    def get_symbol_table_index(self):       # there is only one
        for (i,h) in enumerate(self.sectionheaders):
            if h.is_symbol_table(): return i
        return -1

    def get_dynamic_symbol_table_index(self):     # there is only one
        for (i,h) in enumerate(self.sectionheaders):
            if h.is_dynamic_symbol_table(): return i
        return -1

    def get_dynamic_table_index(self):      # there is only one
        for (i,h) in enumerate(self.sectionheaders):
            if h.is_dynamic_table(): return i
        return -1

    def get_string_table(self,index):
        if index in self.sections:
            return self.sections[index]
        else:
            sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,index)
            if sectionx is None:
                print('Section ' + str(index) + ' could not be found')
                return
            else:
                self.sections[index] = ELFStringTable(self,sectionx,self.sectionheaders[index])
                return self.sections[index]

    def get_string_tables(self):
        indices = self.get_string_table_indices()
        result = []
        for index in indices:
            if index in self.sections:
                result.append(self.sections[index])
            else:
                sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,index)
                if sectionx is None:
                    print('Section ' + str(index) + ' could not be found')
                    return
                else:
                    self.sections[index] = ELFStringTable(self,sectionx,self.sectionheaders[index])
                    result.append(self.sections[index])
        return result

    def get_raw_sections(self):
        for (index,h) in enumerate(self.sectionheaders):
            sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,index)
            if sectionx is None:
                print('Section ' + str(index) + ' could not be found')
                continue
            else:
                self.sections[index] = ELFSection(self,sectionx,self.sectionheaders[index])

    def get_memory_value(self,address,index):
        if not index in self.sections:
            self.get_raw_sections()
        if index in self.sections:
            return self.sections[index].get_byte_value(address)
        else:
            return None

    def get_elf_section_index(self,address):
        for h in self.sectionheaders:
            vaddr = int(h.get_vaddr(),16)
            size = int(h.get_size(),16)
            if address >= vaddr and address < vaddr + size:
                return h.index
        return None

    def get_symbol_table(self):
        index = self.get_symbol_table_index()
        if index in self.sections:
            return self.sections[index]
        else:
            sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,index)
            if sectionx is None:
                print('Section ' + str(index) + ' could not be found')
                return
            else:
                self.sections[index] = ELFSymbolTable(self,sectionx,self.sectionheaders[index])
                return self.sections[index]

    def get_dynamic_symbol_table(self):
        index = self.get_dynamic_symbol_table_index()
        if index in self.sections:
            return self.sections[index]
        else:
            sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,index)
            if sectionx is None:
                print('Section ' + str(index) + ' could not be found')
                return
            else:
                self.sections[index] = ELFSymbolTable(self,sectionx,self.sectionheaders[index])
                return self.sections[index]

    def get_relocation_tables(self):
        result = []
        for sh in self.sectionheaders:
            if sh.is_relocation_table():
                if not sh.index in self.sections:
                    sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,sh.index)
                if sectionx is None:
                    print('Section ' + str(index) + ' could not be found')
                    continue
                else:
                    self.sections[sh.index] = ELFRelocationTable(self,sectionx,self.sectionheaders[sh.index])
                result.append((sh,self.sections[sh.index]))
        return result

    def get_dynamic_table(self):
        index = self.get_dynamic_table_index()
        if index in self.sections:
            return self.sections[index]
        else:
            sectionx = UF.get_elf_section_xnode(self.app.path,self.app.filename,index)
            if sectionx is None:
                print('Section ' + str(index) + ' could not be found')
                return
            else:
                self.sections[index] = ELFDynamicTable(self,sectionx,self.sectionheaders[index])
                return self.sections[index]


    def as_dictionary(self):
        ## note: update for multiple string tables
        ##       add relocation tables
        try:
            result = {}
            result['name'] = self.app.filename
            result['fileheader'] = {}
            result['programheaders'] = []
            result['sectionheaders'] = []
            fileheader = self.get_file_header()
            localetable = UF.get_locale_tables(categories=["ELF"])
            for p in fileheader_attributes:
                propertyvalue = fileheader.get(p)
                if p in valuedescriptor:
                    propertyvalue = valuedescriptor[p](propertyvalue)
                result['fileheader'][p] = {}
                result['fileheader'][p]['value'] = propertyvalue
                result['fileheader'][p]['heading'] = localetable['elfheader'][p]
            for p in self.programheaders:
                result['programheaders'].append(p.as_dictionary())
            for s in self.sectionheaders:
                result['sectionheaders'].append(s.as_dictionary())
            if  self.has_string_table():
                result['stringtables'] = {}
                for s in self.get_string_tables():
                    result['stringtables'][s.get_name()] = s.as_dictionary()
            if self.has_symbol_table():
                result['symboltable'] = self.get_symbol_table().as_dictionary()
            if self.has_dynamic_symbol_table():
                result['dynamicsymboltable'] = self.get_dynamic_symbol_table().as_dictionary()
            if self.has_dynamic_table():
                result['dynamictable'] = self.get_dynamic_table().as_dictionary()
            return result
        except KeyError as e:
            raise UF.KTKeyError(str(e))

    def section_layout_to_string(self):
        lines = []
        lines.append('\nSection Layout\n')
        lines.append('index'.ljust(8)
                         + 'name'.ljust(16) + 'start'.rjust(10) + 'size'.rjust(10)
                         + '   ' + 'flags')
        lines.append('-' * 80)
        for s in sorted(self.sectionheaders,key=lambda s:s.index):
            lines.append(str(s.index).rjust(3) + '     '
                             + s.name.ljust(16) + s.get_vaddr().rjust(10)
                             + s.get_size().rjust(10)
                             + '   ' + s.get_flags_string())
        return '\n'.join(lines)

    def __str__(self):
        d = self.as_dictionary()
        lines = []
        for k in d['fileheader']:
            lines.append(str(d['fileheader'][k]['heading']).ljust(35)
                             + ': ' + str(d['fileheader'][k]['value']))
        lines.append('\nProgram Headers')
        lines.append('-' * 80)
        for p in self.programheaders:
            lines.append('Program header ' + str(p.get_index()))
            lines.append(str(p))
            lines.append(' ')
        for s in sorted(self.sectionheaders,key=lambda s:s.index):
            lines.append('Section header ' + str(s.index) + ' (' + str(s.name) + ')')
            lines.append(str(s))
            lines.append(' ')
        if self.has_string_table():
            for s in self.get_string_tables():
                lines.append('\nString table: ' + s.get_name())
                lines.append(str(s))
        if self.has_symbol_table():
            symtab = self.get_symbol_table()
            lines.append('\nSymbol Table')
            lines.append('-- linked string table section: '
                             + str(int(symtab.sectionheader.get_linked_section(),16)))
            lines.append(str(symtab))
        if self.has_dynamic_symbol_table():
            symtab = self.get_dynamic_symbol_table()
            lines.append('\nDynamic Symbol Table')
            lines.append('-- linked string table section: '
                             + str(int(symtab.sectionheader.get_linked_section(),16)))
            lines.append(str(symtab))
        for (sh,s) in self.get_relocation_tables():
            lines.append('\nRelocation Table '  + str(sh.index) + ' (' + str(sh.name) + ')')
            lines.append('-- linked symbol table section: '
                             + str(int(sh.get_linked_section(),16)))
            lines.append(str(s))
        if self.has_dynamic_table():
            table = self.get_dynamic_table()
            lines.append('\nDynamic Table')
            lines.append('-- linked string table section: '
                             + str(int(table.sectionheader.get_linked_section(),16)))
            lines.append(str(self.get_dynamic_table()))
        lines.append(self.section_layout_to_string())
        return '\n'.join(lines)

    def _initialize(self):
        programheaders = self.xnode.find('elf-program-headers')
        for ph in programheaders.findall('program-header'):
            self.programheaders.append(ELFProgramHeader(self,ph))
        sectionheaders = self.xnode.find('elf-section-headers')
        for sh in sectionheaders.findall('section-header'):
            self.sectionheaders.append(ELFSectionHeader(self,sh))
        xdictionary = UF.get_elf_dictionary_xnode(self.app.path,self.app.filename)
        self.dictionary.initialize(xdictionary)
    
