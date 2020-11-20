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

import chb.util.IndexedTable as IT

symbolbindings = {
    0: 'LOCAL',
    1: 'GLOBAL',
    2: 'WEAK'
    }

def get_symbol_binding_desc(i):
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

def get_symbol_type_desc(i):
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

def get_dynamic_array_tag_name(i):
    if i in dynamicarraytags:
        return dynamicarraytags[i]
    else:
        return str(i)

class ELFSection(object):

    def __init__(self,elfheader,xnode,sectionheader):
        self.elfheader = elfheader
        self.xnode = xnode
        self.sectionheader = sectionheader
        self.values = None     # int -> value (byte values)

    def get_name(self): return self.sectionheader.name

    def get_byte_value(self,address):
        if not self.values:
            self._initialize_section()
        if address in self.values:
            return self.values[address]

    def get_string(self,address):
        b = self.get_byte_value(address)
        result = ''
        while b:
            result += chr(b)
            address += 1
            b = self.get_byte_value(address)
        return result

    def get_linked_stringtable(self):
        shlink = int(self.sectionheader.get_linked_section(),16)
        return self.elfheader.get_string_table(shlink)

    def _initialize_section(self):
        self.values = {}
        hexdata = self.xnode.find('hex-data')
        blockcount = hexdata.get('blocks')
        for blockdata in hexdata.findall('ablock'):
            for hexline in blockdata.findall('aline'):
                address = int(hexline.get('va'),16)
                bytestring = hexline.get('bytes')
                bytestring = bytestring.replace(' ','')
                for i in range(0,len(bytestring),2):
                    byteval = bytestring[i:i+2]
                    self.values[address+(i//2)] = int(byteval,16)


class ELFStringTable(ELFSection):

    def __init__(self,elfheader,xnode,sectionheader):
        ELFSection.__init__(self,elfheader,xnode,sectionheader)
        self.strings = {}        
        self._initialize()

    def get_string(position):
        if position < 0: return '**invalid**'
        if position == 0: return ''
        if position in self.strings:
            return self.strings[position]
        else:
            prev = 0
            for p in sorted(strings):
                if position < p:
                    return self.strings[prev][(position-prev):]
        return '**index out of bounds**'

    def as_dictionary(self): return self.strings

    def __str__(self):
        lines = []
        for p in sorted(self.strings):
            lines.append(str(p).rjust(4) + ' : ' + str(self.strings[p]))
        return '\n'.join(lines)
            

    def _initialize(self):
        stringtable = self.xnode.find('data').find('string-table')
        for c in stringtable.findall('str'):
            self.strings[int(c.get('p')) ] = c.get('s')

class ELFSymbol(object):

    """
    rep-record representation:
    tags: 0: st_name (hex-string)
          1: st_value (hex-string)
          2: st_size (hex-string)
    args: 0: name (string-index)
          1: st_info
          2: st_other
          3: st_shndx
    """

    def __init__(self,symboltable,xnode):
        self.symboltable = symboltable
        self.stringtable = self.symboltable.stringtable
        self.xnode = xnode
        self.dictionary = self.symboltable.elfheader.dictionary
        rep = IT.get_rep(xnode,indextag='id')
        self.id = rep[0]
        self.tags = rep[1]
        self.args = rep[2]

    def get_name(self):
        return self.dictionary.get_string(int(self.args[0]))

    def get_info(self): return self.args[1]

    def get_binding(self):
        # st_bind = st_info >> 4
        return get_symbol_binding_desc(self.get_info() >> 4)

    def get_type(self):
        # st_type = st_info & 15
        return get_symbol_type_desc(self.get_info() & 15)

    def get_section_index(self): return int(self.args[3])

    def get_size(self): return int(self.tags[2],16)

    def as_dictionary(self):
        result = {}
        result['name'] = self.get_name()
        result['value'] = self.tags[1]
        result['binding'] = self.get_binding()
        result['type'] = self.get_type()
        result['size'] = self.get_size()
        result['section'] = self.get_section_index()
        return result

    def __str__(self):
        d = self.as_dictionary()
        lines = []
        for k in sorted(d):
            lines.append('  ' + str(k).rjust(10) + ': ' + str(d[k]))
        return '\n'.join(lines)

class ELFSymbolTable(ELFSection):

    def __init__(self,elfheader,xnode,sectionheader):
        ELFSection.__init__(self,elfheader,xnode,sectionheader)
        self.symbols = {}
        self.stringtable = self.get_linked_stringtable()
        self._initialize()

    def as_dictionary(self):
        result = {}
        for i in self.symbols:
            result[i] = self.symbols[i].as_dictionary()
        return result

    def __str__(self):
        lines = []
        for i in self.symbols:
            lines.append('Symbol ' + str(i))
            lines.append(str(self.symbols[i]))
        return '\n'.join(lines)

    def _initialize(self):
        symboltable = self.xnode.find('data').find('symbol-table')
        for r in symboltable.findall('n'):
            self.symbols[int(r.get('id'))] = ELFSymbol(self,r)


class ELFRelocationEntry(object):

    """
    rep-record representation:
    tags: 0: r_offset (hex-string)
          1: r_info  (hex-string)
          2: symbol-value (hex-string)
    args: 0: type (r_info & 255)
          1: name (string-index)
    """

    def __init__(self,relocationtable,xnode):
        self.relocationtable = relocationtable
        self.xnode = xnode
        self.dictionary = self.relocationtable.elfheader.dictionary
        rep = IT.get_rep(xnode,indextag='id')
        self.id = rep[0]
        self.tags = rep[1]
        self.args = rep[2]
        
    def get_symbol_name(self):
        return self.dictionary.get_string(self.args[1])

    def get_type(self): return self.args[0]

    def get_symbol_value(self): return self.tags[2]

    def get_r_offset(self): return self.tags[0]

    def as_dictionary(self):
        result = {}
        result['symbolname'] = self.get_symbol_name()
        result['offset'] = self.get_r_offset()
        return result

    def __str__(self):
        return (self.get_r_offset() + ': ' + self.get_symbol_name())

class ELFRelocationTable(ELFSection):

    def __init__(self,elfheader,xnode,sectionheader):
        ELFSection.__init__(self,elfheader,xnode,sectionheader)
        self.entries = []
        self._initialize()

    def as_dictionary(self):
        result = {}
        for entry in self.entries:
            result[entry.id] = entry.as_dictionary()
        return result

    def __str__(self):
        lines = []
        for e in sorted(self.entries,key=lambda x:x.get_r_offset()):
            lines.append(str(e))
        return '\n'.join(lines)

    def _initialize(self):
        reltable = self.xnode.find('data').find('relocation-table')
        for r in reltable.findall('n'):
            self.entries.append(ELFRelocationEntry(self,r))

class ELFDynamicEntry(object):

    def __init__(self,dynamictable,xnode):
        self.dynamictable = dynamictable
        self.xnode = xnode
        rep = IT.get_rep(xnode,indextag='id')
        self.id = rep[0]
        self.tags = rep[1]
        self.d_tag = self.tags[0]
        self.d_un = self.tags[1]

    def get_tag_name(self): return get_dynamic_array_tag_name(int(self.d_tag))

    def get_value(self):
        if self.get_tag_name() == 'DT_PLTREL':
            if self.d_un ==  '0x11':
                return 'DT_REL'
            elif self.d_un ==  '0x7':
                return 'DT_RELA'
            else:
                return self.d_un
        return self.d_un

    def as_dictionary(self):
        result = {}
        result['tag'] = self.get_tag_name()
        result['value'] = self.get_value()
        return result

    def __str__(self):
        return (self.get_tag_name().ljust(10) + ': ' + str(self.get_value()))
        

class ELFDynamicTable(ELFSection):

    def __init__(self,elfheader,xnode,sectionheader):
        ELFSection.__init__(self,elfheader,xnode,sectionheader)
        self.entries = []
        self._initialize()

    def as_dictionary(self):
        result = {}
        for (i,entry) in enumerate(self.entries):
            result[str(i)] = entry.as_dictionary()
        return result

    def __str__(self):
        lines = []
        for e in self.entries:
            lines.append(str(e))
        return '\n'.join(lines)

    def _initialize(self):
        dtable = self.xnode.find('data').find('dynamic-table')
        for r in dtable.findall('n'):
            self.entries.append(ELFDynamicEntry(self,r))
