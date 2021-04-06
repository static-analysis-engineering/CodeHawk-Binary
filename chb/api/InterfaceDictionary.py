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

import chb.api.CallTarget as CT

function_stub_constructors = {
    'so': lambda x:CT.SOFunction(*x),
    'sc': lambda x:CT.SyscallFunction(*x),
    'dll': lambda x:CT.DllFunction(*x),
    'jni': lambda x:CT.JniFunction(*x),
    'pck': lambda x:CT.PckFunction(*x)
    }

call_target_constructors = {
    'stub': lambda x:CT.StubTarget(*x),
    'sstub': lambda x:CT.StaticStubTarget(*x),
    'app': lambda x:CT.AppTarget(*x),
    'inl': lambda x:CT.InlinedAppTarget(*x),
    'wrap': lambda x:CT.WrappedTarget(*x),
    'v': lambda x:CT.VirtualTarget(*x),
    'i': lambda x:CT.IndirectTarget(*x),
    'u': lambda x:CT.UnknownTarget(*x)
    }

class InterfaceDictionary(object):

    def __init__(self,app,xnode):
        self.app = app
        self.bdictionary = self.app.bdictionary
        self.function_stub_table = IT.IndexedTable('function-stub-table')
        self.call_target_table = IT.IndexedTable('call-target-table')
        self.tables = [
            (self.function_stub_table, self._read_xml_function_stub_table),
            (self.call_target_table, self._read_xml_call_target_table)
            ]
        self.initialize(xnode)

    # -------------- Retrieve items from dictionary tables ---------------------

    def get_function_stub(self,ix): return self.function_stub_table.retrieve(ix)

    def get_call_target(self,ix): return self.call_target_table.retrieve(ix)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_call_target(self,n):
        return self.get_call_target(int(n.get('ictgt')))

    # ---------------- Initialize dictionary from file -------------------------

    def initialize(self,xnode):
        if xnode is None: return
        for (t,f) in self.tables:
            t.reset()
            f(xnode.find(t.name))

    def _read_xml_function_stub_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return function_stub_constructors[tag](args)
        self.function_stub_table.read_xml(txnode,'n',get_value)

    def _read_xml_call_target_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,)  + rep
            return call_target_constructors[tag](args)
        self.call_target_table.read_xml(txnode,'n',get_value)
        
