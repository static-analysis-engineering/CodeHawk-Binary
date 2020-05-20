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

sectionheadertypes =  {
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

def get_section_header_type(s):
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
    11: "COMPRESSED"
    }

def get_section_header_flag(i):
    if i in sectionheaderflags:
        return sectionheaderflags[i]
    else: return '?'

def get_section_header_flags(flags):
    binstring = bin(int(flags,16))[2:].zfill(32)
    result = ''
    for (i,c) in enumerate(str(binstring)):
        if c == "0": continue
        result += ' ' + get_section_header_flag(31-i)
    return result
        
class ELFSectionHeader():

    def __init__(self,elfheader,xnode):
        self.elfheader = elfheader
        self.xnode = xnode
        self.name = self.xnode.get('name')
        self.index = int(self.xnode.get('index'))

    def get_section_header_type(self):
        shtype = self.xnode.get('sh_type','0x0')
        return get_section_header_type(shtype)

    def get_vaddr(self):
        return self.xnode.get('sh_addr','0x0')

    def get_size(self):
        return self.xnode.get('sh_size','0x0')

    def get_flags_string(self):
        shflags = self.xnode.get('sh_flags','0x0')
        return get_section_header_flags(shflags)

    def get_linked_section(self):
        return self.xnode.get('sh_link')

    def is_string_table(self):
        return self.get_section_header_type() == 'SHT_StrTab'

    def is_symbol_table(self):
        return self.get_section_header_type() == 'SHT_SymTab'

    def is_dynamic_symbol_table(self):
        return self.get_section_header_type() == 'SHT_DynSym'

    def is_relocation_table(self):
        return self.get_section_header_type() == 'SHT_Rel'

    def is_dynamic_table(self):
        return self.get_section_header_type() == 'SHT_Dynamic'

    def as_dictionary(self):
        result = {}
        result['index'] = int(self.xnode.get('index'));
        result['name'] = self.xnode.get('name')
        localetable = UF.get_locale_tables(tables=[ ("ELF","elfsectionheader")  ])
        for p in sectionheader_attributes:
            propertyvalue = self.xnode.get(p,'0x0')
            if p == 'sh_type':
                propertyvalue = get_section_header_type(propertyvalue)
            if p == 'sh_flags':
                flags = get_section_header_flags(propertyvalue)
                if len(flags) > 0:
                    propertyvalue += ' (' + flags + ')'
            result[p] = {}
            result[p]['value'] = propertyvalue
            result[p]['heading'] = localetable['elfsectionheader'][p]
        return result

    def __str__(self):
        d = self.as_dictionary()
        lines = []
        for k in sorted(d):
            if k == 'index': continue
            if k == 'name': continue
            lines.append(str(d[k]['heading']).ljust(18) + ': ' + str(d[k]['value']))
        return '\n'.join(lines)
        
