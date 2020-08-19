# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
import chb.util.StringIndexedTable as SI

import chb.mips.MIPSOperand as MOP
import chb.mips.MIPSOperandKind as MOPK
import chb.mips.MIPSOpcode as MOPC

mips_opkind_constructors = {
    'a': lambda x:MOPK.MIPSAbsoluteOp(*x),
    'i': lambda x:MOPK.MIPSIndirectRegisterOp(*x),
    'f': lambda x:MOPK.MIPSFloatingPointRegisterOp(*x),
    'm': lambda x:MOPK.MIPSImmediateOp(*x),
    'r': lambda x:MOPK.MIPSRegisterOp(*x),
    's': lambda x:MOPK.MIPSSpecialRegisterOp(*x)
    }

class MIPSDictionary(object):

    def __init__(self,app,xnode):
        self.app = app
        self.opkind_table = IT.IndexedTable('mips-opkind-table')
        self.operand_table = IT.IndexedTable('mips-operand-table')
        self.opcode_table = IT.IndexedTable('mips-opcode-table')
        self.bytestring_table = SI.StringIndexedTable('mips-bytestring-table')
        self.tables = [
            (self.opkind_table,self._read_xml_mips_opkind_table),
            (self.operand_table,self._read_xml_mips_operand_table),
            (self.opcode_table,self._read_xml_mips_opcode_table)
            ]
        self.string_tables = [
            (self.bytestring_table,self._read_xml_mips_bytestring_table),
            ]
        self.initialize(xnode)
    
    # ------------------- retrieve items from dictionary tables ----------------

    def get_mips_opkind(self,ix): return self.opkind_table.retrieve(ix)

    def get_mips_operand(self,ix): return self.operand_table.retrieve(ix)

    def get_mips_opcode(self,ix): return self.opcode_table.retrieve(ix)

    def get_mips_bytestring(self,ix): return self.bytestring_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_mips_opcode(self,n):
        return self.get_mips_opcode(int(n.get('iopc')))

    def read_xml_mips_bytestring(self,n):
        return self.get_mips_bytestring(int(n.get('ibt')))

    # ----------------------- initialize dictionary from file ------------------

    def initialize(self,xnode):
        if xnode is None: return
        for (t,f) in self.tables + self.string_tables:
            t.reset()
            f(xnode.find(t.name))

    def _read_xml_mips_opkind_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return mips_opkind_constructors[tag](args)
        self.opkind_table.read_xml(txnode,'n',get_value)

    def _read_xml_mips_operand_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return MOP.MIPSOperand(*args)
        self.operand_table.read_xml(txnode,'n',get_value)

    def _read_xml_mips_opcode_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return MOPC.get_mips_opcode(tag,args)
        self.opcode_table.read_xml(txnode,'n',get_value)

    def _read_xml_mips_bytestring_table(self,txnode):
        self.bytestring_table.read_xml(txnode)

