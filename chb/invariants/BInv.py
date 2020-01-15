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


class InvDictionaryRecord(object):

    def __init__(self,invd,index,tags,args):
        self.invd = invd
        self.vard = self.invd.vard
        self.xd = self.invd.xd
        self.index = index
        self.tags = tags
        self.args = args

    def get_key(self):
        return (','.join(self.tags), ','.join( [ str(x) for x in self.args ]))


# ------------------------------------------------------------------------------
# Non-relational values
# ------------------------------------------------------------------------------
class NonRelationalValue(InvDictionaryRecord):

    def __init__(self,invd,index,tags,args):
        InvDictionaryRecord.__init__(self,invd,index,tags,args)

    def __str__(self): return 'nrv:' + self.tags[0]

class NRVSymbolicExpr(NonRelationalValue):

    def __init__(self,invd,index,tags,args):
        NonRelationalValue.__init__(self,invd,index,tags,args)

    def get_expr(self): return self.xd.get_xpr(int(self.args[0]))

    def __str__(self): return str(self.get_expr())

class NRVIntervalValue(NonRelationalValue):

    def __init__(self,invd,index,tags,args):
        NonRelationalValue.__init__(self,invd,index,tags,args)

    def get_lb(self):
        lbix = int(self.args[0])
        return self.xd.get_numerical(lbix).get_value() if lbix > 0 else None

    def get_ub(self):
        ubix = int(self.args[0])
        return self.xd.get_numerical(ubix).get_value() if ubix > 0 else None

    def __str__(self):
        lb = self.get_lb()
        ub = self.get_ub()
        if lb == ub:
            return str(lb)
        if lb and ub:
            return '[' + str(lb) + ';' + str(ub) + ']'
        if lb:
            return '[' + str(lb) + '; ->'
        if ub:
            return '<- ; ' + str(ub)

class NRVBaseOffsetValue(NonRelationalValue):

    def __init__(self,invd,index,tags,args):
        NonRelationalValue.__init__(self,invd,index,tags,args)

    def get_base(self):
        return self.xd.get_symbol(int(self.args[0]))

    def get_lb(self):
        lbix = int(self.args[1])
        return self.xd.get_numerical(lbix).get_value() if lbix > 0 else None

    def get_ub(self):
        ubix = int(self.args[2])
        return self.xd.get_numerical(ubix).get_value()  if ubix > 0 else None

    def __str__(self):
        lb = self.get_lb()
        ub = self.get_ub()
        if lb == ub:
            if lb == 0: return str(self.get_base())
            return str(self.get_base()) + ' + ' + str(lb)
        if lb and ub:
            return str(self.get_base()) + '[' + str(lb) + ';' + str(ub) + ']'
        if lb:
            return str(self.get_base()) + '[' + str(lb) + '; ->'
        if ub:
            return str(self.get_base()) + '<- ; ' + str(ub)


# ------------------------------------------------------------------------------
# Linear equality
# ------------------------------------------------------------------------------
class LinearEquality(InvDictionaryRecord):

    def __init__(self,invd,index,tags,args):
        InvDictionaryRecord.__init__(self,invd,index,tags,args)

    def get_constant(self): return int(self.tags[0])

    def get_coeffs(self): return [ int(x) for x in self.tags[1:] ]

    def get_factors(self):
        return [ self.xd.get_variable(int(i)) for i in self.args ]

    def __str__(self):
        cfs = zip(self.get_coeffs(), self.get_factors())
        def term(c,f):
            if c == 1: return str(f)
            if c == -1: return '-' + str(f)
            return str(c)  + '.' + str(f)
        terms = ' + '.join([ term(c,f) for (c,f) in cfs ])
        return terms + ' = ' + str(self.get_constant())


# ------------------------------------------------------------------------------
# Invariant Facts
# ------------------------------------------------------------------------------
class InvariantFact(InvDictionaryRecord):

    def __init__(self,invd,index,tags,args):
        InvDictionaryRecord.__init__(self,invd,index,tags,args)

    def __str__(self):  return  'fact:' + self.tags[0]

class UnreachableFact(InvariantFact):

    def __init__(self,invd,index,tags,args):
        InvariantFact.__init__(self,invd,index,tags,args)
        

class NRVFact(InvariantFact):

    def __init__(self,invd,index,tags,args):
        InvariantFact.__init__(self,invd,index,tags,args)

    def get_var(self): return self.xd.get_variable(int(self.args[0]))

    def get_nrv(self): return self.invd.get_non_relational_value(int(self.args[1]))

    def __str__(self):
        return (str(self.get_var()) + ' == ' + str(self.get_nrv()))

class InitialVarEqualityFact(InvariantFact):

    def __init__(self,invd,index,tags,args):
        InvariantFact.__init__(self,invd,index,tags,args)

    def get_var1(self): return self.xd.get_variable(int(self.args[0]))

    def get_var2(self): return self.xd.get_variable(int(self.args[1]))

    def __str__(self):
        return (str(self.get_var1()) + ' == ' + str(self.get_var2()))

class InitialVarDisEqualityFact(InvariantFact):

    def __init__(self,invd,index,tags,args):
        InvariantFact.__init__(self,invd,index,tags,args)

    def get_var1(self): return self.xd.get_variable(int(self.args[0]))

    def get_var2(self): return self.xd.get_variable(int(self.args[1]))

    def __str__(self):
        return (str(self.get_var1()) + ' <> ' + str(self.get_var2()))

class TestVarEqualityFact(InvariantFact):

    def __init__(self,invd,index,tags,args):
        InvariantFact.__init__(self,invd,index,tags,args)

    def get_var1(self): return self.xd.get_variable(int(self.args[0]))

    def get_var2(self): return self.xd.get_variable(int(self.args[1]))

    def get_loc1(self): return self.tags[1]

    def get_loc2(self): return self.tags[2]

    def __str__(self):
        return (str(self.get_var1()) + '@' + self.get_loc1() + ' = '
                    + str(self.get_var2()) + '@' + self.get_loc2())

class RelationalFact(InvariantFact):

    def __init__(self,invd,index,tags,args):
        InvariantFact.__init__(self,invd,index,tags,args)

    def get_equality(self): return self.invd.get_linear_equality(int(self.args[0]))

    def __str__(self): return str(self.get_equality())
