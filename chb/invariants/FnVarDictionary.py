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

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

import chb.invariants.BVar as BV

from chb.invariants.FnXprDictionary import FnXprDictionary

memory_base_constructors = {
    'l': lambda x:BV.MemoryBaseLocalStackFrame(*x),
    'r': lambda x:BV.MemoryBaseRealignedStackFrame(*x),
    'a': lambda x:BV.MemoryBaseAllocatedStackFrame(*x),
    'g': lambda x:BV.MemoryBaseGlobal(*x),
    'v': lambda x:BV.MemoryBaseBaseVar(*x),
    'u': lambda x:BV.MemoryBaseUnknown(*x)
    }

memory_offset_constructors = {
    'n': lambda x:BV.MemoryOffsetNoOffset(*x),
    'c': lambda x:BV.MemoryOffsetConstantOffset(*x),
    'i': lambda x:BV.MemoryOffsetIndexOffset(*x),
    'u': lambda x:BV.MemoryOffsetUnknown(*x)
    }

assembly_variable_denotation_constructors = {
    'm': lambda x:BV.MemoryVariable(*x),
    'r': lambda x:BV.RegisterVariable(*x),
    'f': lambda x:BV.CPUFlagVariable(*x),
    'a': lambda x:BV.AuxiliaryVariable(*x)
    }

constant_value_variable_constructors = {
    'ir': lambda x:BV.InitialRegisterValue(*x),
    'iv': lambda x:BV.InitialMemoryValue(*x),
    'ft': lambda x:BV.FrozenTestValue(*x),
    'fr': lambda x:BV.FunctionReturnValue(*x),
    'fp': lambda x:BV.FunctionPointer(*x),
    'ct': lambda x:BV.CallTargetValue(*x),
    'se': lambda x:BV.SideEffectValue(*x),
    'ma': lambda x:BV.MemoryAddress(*x),
    'bv': lambda x:BV.BridgeVariable(*x),
    'fv': lambda x:BV.FieldValue(*x),
    'sv': lambda x:BV.SymbolicValue(*x),
    'sp': lambda x:BV.SpecialValue(*x),
    'rt': lambda x:BV.RuntimeConstant(*x)
    }

class FnVarDictionary(object):

    def __init__(self,asmf,xnode):
        self.asmfunction = asmf               # AsmFunction or MIPSFunction
        self.app = self.asmfunction.app
        self.finfo = self.app.get_function_info(self.asmfunction.faddr)
        self.bdictionary = self.app.bdictionary
        self.xd = FnXprDictionary(self,xnode.find('xpr-dictionary'))
        self.memory_base_table = IT.IndexedTable('memory-base-table')
        self.memory_offset_table =  IT.IndexedTable('memory-offset-table')
        self.assembly_variable_denotation_table = IT.IndexedTable('assembly-variable-denotation-table')
        self.constant_value_variable_table = IT.IndexedTable('constant-value-variable-table')
        self.tables = [
            (self.memory_base_table,self._read_xml_memory_base_table),
            (self.memory_offset_table,self._read_xml_memory_offset_table),
            (self.assembly_variable_denotation_table,self._read_xml_assembly_variable_denotation_table),
            (self.constant_value_variable_table,self._read_xml_constant_value_variable_table)
            ]
        self.string_tables = []
        self.initialize(xnode)

    # ------------------------------------------- Retrieve dictionary tables ---

    def get_constant_value_variables(self):
        return self.constant_value_variable_table.values()

    # -------------------------------- Retrieve Items from dictionary tables ---

    def get_memory_base(self,ix): return self.memory_base_table.retrieve(ix)

    def get_memory_offset(self,ix): return self.memory_offset_table.retrieve(ix)

    def get_assembly_variable_denotation(self,ix):
        return self.assembly_variable_denotation_table.retrieve(ix)

    def get_constant_value_variable(self,ix):
        return self.constant_value_variable_table.retrieve(ix)

    # -------------------------------------- Initialize dictionary from file ---

    def initialize(self,xnode):
        if not xnode is None:
            for (t,f) in self.tables + self.string_tables:
                f(xnode.find(t.name))

    def  _read_xml_memory_base_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return memory_base_constructors[tag](args)
        self.memory_base_table.read_xml(txnode,'n',get_value)

    def _read_xml_memory_offset_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return memory_offset_constructors[tag](args)
        self.memory_offset_table.read_xml(txnode,'n',get_value)

    def _read_xml_assembly_variable_denotation_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return assembly_variable_denotation_constructors[tag](args)
        self.assembly_variable_denotation_table.read_xml(txnode,'n',get_value)

    def _read_xml_constant_value_variable_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return constant_value_variable_constructors[tag](args)
        self.constant_value_variable_table.read_xml(txnode,'n',get_value)
            
            
        

    

