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

import chb.util.fileutil as UF

section_header_attributes = [
    "characteristics",
    "number-of-line-numbers",
    "number-of-relocations",
    "pointer-to-raw-data",
    "size-of-raw-data",
    "virtual-address",
    "virtual-size"
    ]

valuedescriptor = {}

class PESectionHeader():
    '''Represents the header data of a single section in the executable.'''

    def __init__(self,peheader,xnode):
        self.peheader = peheader
        self.xnode = xnode
        self.name = self.xnode.get('name')
        self.characteristics = self.xnode.get('characteristics')
        self.numberoflinenumbers = self.xnode.get('number-of-line-numbers')
        self.numberofrelocations = self.xnode.get('number-of-relocations')
        self.pointertorawdata = self.xnode.get('pointer-to-raw-data')
        self.pointertorelocations = self.xnode.get('pointer-to-relocations')
        self.sizeofrawdata = self.xnode.get('size-of-raw-data')
        self.va = self.xnode.get('virtual-address')
        self.virtualsize = self.xnode.get('virtual-size')

    def str_characteristics(self):
        lines = []
        for x in self.xnode.find('section-charxs').findall('charx'):
            lines.append((' ' * 3) + x.get('name'))
        return lines

    def is_executable(self):
        for x in self.xnode.find('section-charxs').findall('charx'):
            if x.get('name') == 'IMAGE_SCN_MEM_EXECUTE': return True
        else:
            return False

    def as_dictionary(self):
        result = {}
        result['name'] = self.name
        localetable = UF.get_locale_tables(tables=[ ("PE","pesectionheader") ])
        for p in section_header_attributes:
            propertyvalue = self.xnode.get(p,'0x0')
            result[p] = {}
            result[p]['value'] = propertyvalue
            result[p]['heading'] = localetable['pesectionheader'][p]
        result['section-characterists'] = sectionxs = {}
        sectionxs['value'] = ','.join(self.str_characteristics())
        sectionxs['heading'] = 'Section characteristics'
        return result

    def __str__(self):
        lines = []
        def addline(tag,value):
            lines.append((' ' * 3) + tag.ljust(32) + ': ' + str(value))
        lines.append('-' * 60)
        lines.append('Section header for ' + self.name)
        lines.append('-' * 60)
        addline('Name', self.name)
        addline('Virtual size', self.virtualsize)
        addline('Virtual address', self.va)
        addline('Size of raw data', self.sizeofrawdata)
        addline('Pointer to raw data', self.pointertorawdata)
        addline('Pointer to relocations', self.pointertorelocations)
        addline('Number of line numbers', self.numberoflinenumbers)
        addline('Number of relocations', self.numberofrelocations)
        addline('Characteristics', self.characteristics)
        lines.append(' ')
        lines.extend(self.str_characteristics())
        lines.append('-' * 60)
        return '\n'.join(lines)
