# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
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
import chb.util.StringIndexedTable as SI
from chb.elfformat.ELFProgramHeader import ELFProgramHeader
from chb.elfformat.ELFSectionHeader import ELFSectionHeader


class ELFDictionary(object):
    '''Indexed types'''

    def __init__(self):
        self.string_table = SI.StringIndexedTable('string-table')
        self.tables = []
        self.string_tables = [
            (self.string_table, self._read_xml_string_table)
            ]

    # -------------- Retrieve items from dictionary tables ---------------------

    def get_string(self,ix): return self.string_table.retrieve(ix)

    def index_string(self,s): return self.string_table.add(s)

    # ----------------------- Initialize dictionary from file ------------------
 
    def initialize(self,xnode):
        if xnode is None: return
        for (t,f) in self.tables + self.string_tables:
            t.reset()
            f(xnode.find(t.name))

    def __str__(self):
        lines = []
        for (t,_) in self.tables:
            if t.size() > 0:
                lines.append(str(t))
        return '\n'.join(lines)

    def _read_xml_string_table(self,txnode): self.string_table.read_xml(txnode)
