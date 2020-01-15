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

xpr_operator_strings = {
    "": " % ",
    "band": " & ",
    "bor": " | ", 
    "bxor": " xor ",
    "bnor": " bnor " ,
    "bnot": " ~",
    "div": " / ",
    "eq": " == ",    
    "ge": " >= " ,
    "gt": " > ",
    "le": " <= " ,
    "lor": " || ",
    "land": " && ",
    "lt": " < ",    
    "minus": " - " ,
    "mod": " % ",
    "mult": " * " ,
    "ne": " <> ",
    "neg": " -",
    "plus": " + ",
    "range": " range ",
    "shiftlt": " << ",
    "shiftrt": " >> "
        }

class XDictionaryRecord(object):
    '''Base class for all objects kept in the XprDictionary.'''

    def __init__(self,xd,index,tags,args):
        self.xd = xd
        self.vd = self.xd.vd
        self.app = self.xd.vd.app
        self.finfo = self.vd.finfo
        self.index = index
        self.tags = tags
        self.args = args

    def get_key(self): return (','.join(self.tags), ','.join([str(x) for x in self.args]))

    def write_xml(self,node):
        (tagstr,argstr) = self.get_key()
        if len(tagstr) > 0: node.set('t',tagstr)
        if len(argstr) > 0: node.set('a',argstr)
        node.set('ix',str(self.index))

class BXBoundBase(XDictionaryRecord):

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def is_min_inf(self): return False
    def is_max_inf(self): return False
    def is_bound(self): return False

class BXMinusInfBound(BXBoundBase):

    def __init__(self,xd,index,tags,args):
        BXBoundBase.__init__(self,xd,index,tags,args)

    def is_min_inf(self): return True

class BXPlusInfBound(BXBoundBase):

    def __init__(self,xd,index,tags,args):
        BXBoundBase.__init__(self,xd,index,tags,args)

    def is_max_inf(self): return True

class BXNumberBound(BXBoundBase):

    def __init__(self,xd,index,tags,args):
        BXBoundBase.__init__(self,xd,index,tags,args)

    def is_bound(self): return True

    def get_bound(self): return self.xd.get_numerical(int(self.args[0]))

class BXNumerical(XDictionaryRecord):
    '''Numerical value.'''

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def get_value(self): return int(self.tags[0])

    def equals(self,other): return (self.get_value() == other.get_value())

    def __str__(self): return self.tags[0]

class BXInterval(XDictionaryRecord):

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def get_lower_bound(self): return self.xd.get_bound(int(self.args[0]))

    def get_upper_bound(self): return self.xd.get_bound(int(self.args[1]))

    def is_closed(self):
        return self.get_lower_bound().is_bound() and self.get_upper_bound().is_bound()

    def is_singleton(self):
        return (self.is_closed()
                    and self.get_lower_bound().get_bound().equals(self.get_upper_bound().get_bound()))

    def __str__(self):
        if self.is_singleton():
            return str(self.get_lower_bound().get_bound().get_value())
        if self.is_closed():
            return (str(self.get_lower_bound().get_bound().get_value()) + ';'
                        + str(self.get_upper_bound().get_bound().get_value()))
        if self.get_lower_bound().is_bound():
            return str(self.get_lower_bound().get_bound().get_value()) + '; oo'
        if self.get_upper_bound().is_bound():
            return 'oo + ;' + str(self.get_upper_bound().get_bound().get_value())
        return 'oo ; oo'


class BXSymbol(XDictionaryRecord):
    '''Symbolic value.'''

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def get_name(self):
        seqnr = self.get_seqnr()
        if self.finfo.has_variable_name(seqnr):
            return self.finfo.get_variable_name(seqnr)
        else:
            return '?' if self.tags[0] == 'tmpN' else self.tags[0]

    def get_attrs(self): return self.tags[1:]

    def get_seqnr(self): return int(self.args[0])

    def __str__(self):
        seqnr = self.get_seqnr()
        if len(self.tags) > 1:
            attrs = '_' + '_'.join(self.get_attrs())
        else:
            attrs = ''
        pseqnr = '_s:' + str(seqnr) if seqnr >= 0 else ''
        return self.get_name() + attrs + pseqnr

class BXVariable(XDictionaryRecord):
    '''CHIF variable.'''

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def is_tmp(self): return (self.get_seqnr() == -1)

    def get_name(self): return self.xd.get_symbol(int(self.args[0])).get_name()

    def get_seqnr(self): return self.xd.get_symbol(int(self.args[0])).get_seqnr()

    def get_type(self): return self.tags[0]

    def has_denotation(self): return self.get_seqnr() > 0

    def get_denotation(self):
        return self.vd.get_assembly_variable_denotation(self.get_seqnr())

    def is_stack_argument(self):
        return (self.get_denotation().is_memory_variable()
                    and self.get_denotation().is_stack_argument())

    def is_argument_value(self):
        return (self.get_denotation().is_auxiliary_variable()
                    and self.get_denotation().get_auxiliary_variable().is_argument_value())

    def is_argument_deref_value(self):
        return (self.get_denotation().is_auxiliary_variable()
                    and self.get_denotation().get_auxiliary_variable().is_argument_deref_value())

    def get_argument_deref_arg_offset(self):
        if self.is_argument_deref_value():
            return self.get_denotation().get_auxiliary_variable().get_argument_deref_arg_offset()
        else:
            raise CHBError('BXpr:Error in get_argument_deref_arg_offset')

    def is_global_value(self):
        return (self.has_denotation()
                    and self.get_denotation().is_auxiliary_variable()
                    and self.get_denotation().get_auxiliary_variable().is_global_value())

    def is_global_variable(self):
        return (self.has_denotation()
                    and ((self.get_denotation().is_memory_variable()
                            and self.get_denotation().is_global_variable())
                            or (self.is_global_value())))

    def has_global_variable_base(self):
        if self.is_global_variable():
            return True
        if self.has_denotation():
            return self.get_denotation().has_global_base()
        return False

    def get_global_variable_base(self):
        v = self.get_denotation()
        if v.is_auxiliary_variable():
            return v.get_auxiliary_variable().get_original_variable().get_denotation().get_global_base()
        else:
            return v.get_global_base()
            
    def get_global_variables(self):
        result = {}
        if self.is_global_variable() or self.has_global_variable_base():
            result[ str(self.get_global_variable_base()) ] = 1
        return result

    def is_structured_var(self):
        return (self.has_denotation() and self.get_denotation().is_structured_var())

    def get_argument_index(self):
        if self.is_argument_value():
            return self.get_denotation().get_auxiliary_variable().get_argument_index()
        elif self.is_stack_argument():
            return self.get_denotation().get_argument_index()

    def __str__(self):
        if self.finfo.has_variable_name(self.get_seqnr()):
            return str(self.get_name())
        else:
            if not self.is_tmp():
                if self.get_denotation().is_bridge_variable():
                    return '?'
                else:
                    return str(self.get_denotation())
            else:
                return (str(self.get_name()))


class BXXCstBase(XDictionaryRecord):
    '''Expression Constant.'''

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def is_string_reference(self,i):
        return self.xd.vd.app.stringxrefs.has_string(str(hex(i)))

    def get_string_reference(self,i):
        return self.xd.vd.app.stringxrefs.get_string(str(hex(i)))

    def is_symset(self): return False
    def is_intconst(self): return False
    def is_boolconst(self): return False
    def is_random(self): return False
    def is_unknown_int(self): return False
    def is_unknown_set(self): return False

    def __str__(self): return 'basexcst:' + self.tags[0]

class BXSymSet(BXXCstBase):

    def __init__(self,xd,index,tags,args):
        BXXCstBase.__init__(self,xd,index,tags,args)

    def is_symset(self): return True

    def get_symbols(self): return [ self.xd.get_symbol(int(i)) for i in self.args ]

    def __str__(self): return '[' + ','.join([str(x) for x in self.get_symbols()]) + ']'


class BXIntConst(BXXCstBase):

    def __init__(self,xd,index,tags,args):
        BXXCstBase.__init__(self,xd,index,tags,args)

    def is_intconst(self): return True

    def get_constant(self): return self.xd.get_numerical(int(self.args[0]))

    def __str__(self):
        if (self.is_string_reference(self.get_constant().get_value())
                and len(self.get_string_reference(self.get_constant().get_value())) > 1):
            return (str(hex(self.get_constant().get_value()))
                        + ': "' + self.get_string_reference(self.get_constant().get_value()) + '"')
        elif self.get_constant().get_value() >  1000:
            return str(hex(self.get_constant().get_value()))
        else:
            return str(self.get_constant())

class BXBoolConst(BXXCstBase):

    def __init__(self,xd,index,tags,args):
        BXXCstBase.__init__(self,xd,index,tags,args)

    def is_boolconst(self): return True

    def is_true(self): return int(self.args[0]) == 1

    def is_false(self): return int(self.args[0]) == 0

    def __str__(self): return 'true' if self.is_true() else 'false'

class BXRandom(BXXCstBase):

    def __init__(self,xd,index,tags,args):
        BXXCstBase.__init__(self,xd,index,tags,args)

    def is_random(self): return True

    def __str__(self): return '??'

class BXUnknownInt(BXXCstBase):

    def __init__(self,xd,index,tags,args):
        BXXCstBase.__init__(self,xd,index,tags,args)

    def is_unknow_nint(self): return True

    def __str__(self): return 'unknown int'

class BXUnknownSet(BXXCstBase):

    def __init__(self,xd,index,tags,args):
        BXXCstBase.__init__(self,xd,index,tags,args)

    def is_unknown_set(self): return True

    def __str__(self): return 'unknown set'


class BXXprBase(XDictionaryRecord):
    '''Analysis base expression.'''

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def is_var(self): return False
    def is_const(self): return False
    def is_int_const_value(self,n): return False
    def is_op(self): return False
    def is_attr(self): return False
    def is_four_multiple(self): return False

    # returns true if this expression is a dereference
    def is_structured_expr(self): return False

    # returns a dictionary gv -> count
    def get_global_variables(self): return {}

    def __str__(self): return 'basexpr:' + self.tags[0]

class BXVar(BXXprBase):

    def __init__(self,xd,index,tags,args):
        BXXprBase.__init__(self,xd,index,tags,args)

    def is_var(self): return True

    def is_structured_expr(self): return self.get_variable().is_structured_var()

    def get_variable(self): return self.xd.get_variable(int(self.args[0]))

    def get_global_variables(self):
        result = {}
        if self.get_variable().is_global_variable():
            result[str(self.get_variable().get_global_variable_base())] = 1
        return result

    def __str__(self): return str(self.get_variable())

class BXConst(BXXprBase):

    def __init__(self,xd,index,tags,args):
        BXXprBase.__init__(self,xd,index,tags,args)

    def is_const(self): return True

    def is_int_const_value(self,n):
        return (self.get_const().is_intconst()
                    and self.get_const().get_constant().get_value() == n)

    def get_negated_value(self):
        return -(self.get_const().get_constant().get_value())

    def get_const(self): return self.xd.get_xcst(int(self.args[0]))

    def get_constant_value(self): return self.get_const().get_constant().get_value()

    def __str__(self): return str(self.get_const())

class BXOp(BXXprBase):

    def __init__(self,xd,index,tags,args):
        BXXprBase.__init__(self,xd,index,tags,args)

    def is_op(self): return True

    def is_structured_expr(self):
        return any([ arg.is_structured_expr() for arg in self.get_args() ])

    def is_four_multiple(self):
        if self.get_op() == 'mult':
            args = self.get_args()
            if len(args) == 2:
                arg1 = args[0]
                arg2 = args[1]
                return (arg1.is_const() and arg1.is_int_const_value(4)
                            or arg2.is_const() and arg2.is_int_const_value(4))
        return False

    def get_quotient_four(self):
        if self.is_four_multiple():
            args = self.get_args()
            arg1 = args[0]
            arg2 = args[1]
            if arg1.is_const() and arg1.is_int_const_value(4):
                return arg2
            else:
                return arg1

    def get_op(self): return self.tags[1]

    def get_args(self): return [ self.xd.get_xpr(int(i)) for i in self.args ]

    def __str__(self):
        args = self.get_args()
        if len(args) == 1:
            return '(' + xpr_operator_strings[self.get_op()]  + str(args[0]) + ')'
        elif len(args) == 2:
            return '(' + str(args[0]) + xpr_operator_strings[self.get_op()] + str(args[1]) + ')'
        else:
            return ('(' + xpr_operator_strings[self.get_op()]
                        + '(' + ','.join(str(x) for x in args) + ')')

class BXAttr(BXXprBase):

    def __init_(self,xd,index,tags,args):
        BXXprBase.__init__(self,xd,index,tags,args)

    def is_attr(self): return True

    def get_attr(self): return self.tags[1]

    def get_xpr(self): return self.xd.get_xpr(int(self.args[0]))

    def __str__(self):
        return 'attr(' + self.get_attr() + ',' + str(self.get_xpr()) + ')'

class BXprList(XDictionaryRecord):

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def get_exprs(self): return [ self.xd.get_xpr(int(i)) for i in self.args ]

    def __str__(self):
        return ' && '.join([str(x) for x in self.get_exprs()])

class BXprListList(XDictionaryRecord):

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def get_expr_lists(self): return [ self.xd.get_xpr_list(int(i)) for i in self.args ]

    def __str__(self):
        return ' || '.join([('(' + str(x) + ')') for x in self.get_expr_lists()])
