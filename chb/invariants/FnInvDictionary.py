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
import chb.util.IndexedTable as IT

import chb.invariants.BInv as BI

non_relational_value_constructors = {
    'sx': lambda x:BI.NRVSymbolicExpr(*x),
    'iv': lambda x:BI.NRVIntervalValue(*x),
    'bv': lambda x:BI.NRVBaseOffsetValue(*x)
    }

invariant_fact_constructors = {
    'u': lambda x:BI.UnreachableFact(*x),
    'n': lambda x:BI.NRVFact(*x),
    'r': lambda x:BI.RelationalFact(*x),
    'ie': lambda x:BI.InitialVarEqualityFact(*x),
    'id': lambda x:BI.InitialVarDisEqualityFact(*x),
    'te': lambda x:BI.TestVarEqualityFact(*x)
    }


class FnInvDictionary(object):

    def __init__(self,vard,xnode):
        self.vard = vard
        self.asmfunction = self.vard.asmfunction
        self.app = self.asmfunction.app
        self.xd = self.vard.xd
        self.non_relational_value_table = IT.IndexedTable("non-relational-value-table")
        self.linear_equality_table = IT.IndexedTable("linear-equality-table")
        self.invariant_fact_table = IT.IndexedTable("invariant-fact-table")
        self.invlist_table = IT.IndexedTable("invariant-list-table")
        self.tables = [
            (self.non_relational_value_table, self._read_xml_non_relational_value_table),
            (self.linear_equality_table,self._read_xml_linear_equality_table),
            (self.invariant_fact_table, self._read_xml_invariant_fact_table) ]
        self.initialize(xnode)

    # ------------------------- Retrieve items from dictionary tables ----------

    def get_non_relational_value(self,ix):
        return self.non_relational_value_table.retrieve(ix)

    def get_linear_equality(self,ix):
        return self.linear_equality_table.retrieve(ix)

    def get_invariant_fact(self,ix):
        return self.invariant_fact_table.retrieve(ix)

    # ---------------------------- Initialize dictionary from file -------------

    def initialize(self,xnode):
        if not xnode is None:
            for (t,f) in self.tables:
                t.reset()
                f(xnode.find(t.name))

    def _read_xml_non_relational_value_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return non_relational_value_constructors[tag](args)
        self.non_relational_value_table.read_xml(txnode,'n',get_value)

    def _read_xml_linear_equality_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return BI.LinearEquality(*args)
        self.linear_equality_table.read_xml(txnode,'n',get_value)

    def _read_xml_invariant_fact_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return invariant_fact_constructors[tag](args)
        self.invariant_fact_table.read_xml(txnode,'n',get_value)
