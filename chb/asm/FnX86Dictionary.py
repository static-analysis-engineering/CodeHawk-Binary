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

import chb.util.IndexedTable as IT

import chb.asm.AsmInstruction as A


class FnX86Dictionary(object):

    def __init__(self,asmf,xnode):
        self.asmfunction = asmf
        self.esp_offset_table = IT.IndexedTable('esp-offset-table')
        self.instrx_table = IT.IndexedTable('instrx-table')
        self.tables = [
            (self.esp_offset_table,self._read_xml_esp_offset_table),
            (self.instrx_table,self._read_xml_instrx_table)
            ]
        self.initialize(xnode)

    # ------------------  retrieve items from dictionary tables ----------------

    def get_esp_offset(self,ix): return self.esp_offset_table.retrieve(ix)

    def get_instrx(self,ix): return self.instrx_table.retrieve(ix)

    # ------------------------ xml accessors -----------------------------------

    def read_xml_esp_offset(self,n):
        return self.get_esp_offset(int(n.get('iesp')))

    def read_xml_instrx(self,n):
        return self.get_instrx(int(n.get('iopx')))

    # -------------------- initialize dictionary from file ---------------------

    def initialize(self,xnode):
        if xnode is None: return
        for (t,f) in self.tables:
            t.reset()
            f(xnode.find(t.name))

    def _read_xml_esp_offset_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return A.EspOffset(*args)
        self.esp_offset_table.read_xml(txnode,'n',get_value)

    def _read_xml_instrx_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return A.AsmInstrXData(*args)
        self.instrx_table.read_xml(txnode,'n',get_value)
        
