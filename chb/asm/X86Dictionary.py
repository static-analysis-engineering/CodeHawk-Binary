# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

import chb.asm.AsmOperand as OP
import chb.asm.OperandKind as OPK
import chb.asm.X86Opcode as OPC

opkind_constructors = {
    'v': lambda x:OPK.FlagOp(*x),
    'r': lambda x:OPK.RegisterOp(*x),
    'f': lambda x:OPK.FpuRegisterOp(*x),
    'c': lambda x:OPK.ControlRegisterOp(*x),
    'd': lambda x:OPK.DebugRegisterOp(*x),
    'm': lambda x:OPK.MmRegisterOp(*x),
    'x': lambda x:OPK.XmmRegisterOp(*x),
    's': lambda x:OPK.SegRegisterOp(*x),
    'ri': lambda x:OPK.IndirectRegisterOp(*x),
    'si': lambda x:OPK.SegIndirectRegisterOp(*x),
    'rs': lambda x:OPK.ScaledIndirectRegisterOp(*x),
    'rd': lambda x:OPK.DoubleRegisterOp(*x),
    'i': lambda x:OPK.ImmediateOp(*x),
    'a': lambda x:OPK.AbsoluteOp(*x),
    'sa': lambda x:OPK.SegAbsoluteOp(*x),
    'u': lambda x:OPK.DummyOp(*x)
    }

class X86Dictionary(object):

    def __init__(self,app,xnode):
        self.app = app
        self.opkind_table = IT.IndexedTable('opkind-table')
        self.operand_table = IT.IndexedTable('operand-table')
        self.opcode_table = IT.IndexedTable('opcode-table')
        self.bytestring_table = SI.StringIndexedTable('bytestring-table')
        self.opcode_text_table = SI.StringIndexedTable('opcode-text-table')
        self.tables = [
            (self.opkind_table,self._read_xml_opkind_table),
            (self.operand_table,self._read_xml_operand_table),
            (self.opcode_table,self._read_xml_opcode_table)
            ]
        self.string_tables = [
            (self.bytestring_table,self._read_xml_bytestring_table),            
            (self.opcode_text_table,self._read_xml_opcode_text_table)
            ]
        self.initialize(xnode)

    def get_instr_bytes(self): return self.bytestring_table.values()

    # ------------------- retrieve items from dictionary tables ----------------

    def get_opkind(self,ix): return self.opkind_table.retrieve(ix)

    def get_operand(self,ix): return self.operand_table.retrieve(ix)

    def get_opcode(self,ix): return self.opcode_table.retrieve(ix)

    def get_bytestring(self,ix): return self.bytestring_table.retrieve(ix)

    def get_opcode_text(self,ix): return self.opcode_text_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_opcode_text(self,n):
        return self.get_opcode_text(int(n.get('itxt')))

    def read_xml_opcode(self,n):
        return self.get_opcode(int(n.get('iopc')))

    def read_xml_bytestring(self,n):
        return self.get_bytestring(int(n.get('ibt')))

    # ----------------------- initialize dictionary from file ------------------

    def initialize(self,xnode):
        if xnode is None: return
        for (t,f) in self.tables + self.string_tables:
            t.reset()
            f(xnode.find(t.name))

    def _read_xml_opkind_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return opkind_constructors[tag](args)
        self.opkind_table.read_xml(txnode,'n',get_value)

    def _read_xml_operand_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return OP.AsmOperand(*args)
        self.operand_table.read_xml(txnode,'n',get_value)

    def _read_xml_opcode_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return OPC.get_opcode(tag,args)
        self.opcode_table.read_xml(txnode,'n',get_value)


    def _read_xml_bytestring_table(self,txnode):
        self.bytestring_table.read_xml(txnode)

    def _read_xml_opcode_text_table(self,txnode):
        self.opcode_text_table.read_xml(txnode)
