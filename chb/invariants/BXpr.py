# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

import chb.invariants.InputConstraint as IC

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
    "ne": " != ",
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

    def get_argument_deref_arg_offset(self,inbytes=False):
        if self.is_argument_deref_value():
            return self.get_denotation().get_auxiliary_variable().get_argument_deref_arg_offset(inbytes)
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
        if self.is_tmp():
            return str(self.get_name())
        denotation = self.get_denotation()
        if denotation.is_bridge_variable():
            return '?'
        if denotation.is_auxiliary_variable():
            auxvar = denotation.get_auxiliary_variable()
            if auxvar.is_function_return_value():
                return str(auxvar)
        return (str(self.get_name()))


class BXXCstBase(XDictionaryRecord):
    '''Expression Constant.'''

    def __init__(self,xd,index,tags,args):
        XDictionaryRecord.__init__(self,xd,index,tags,args)

    def is_string_reference(self): return False

    def get_string_reference(self): return None

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

    def is_string_reference(self):
        xval = self.get_constant().get_value()
        return self.xd.vd.app.stringxrefs.has_string(str(hex(xval)))

    def get_string_reference(self):
        xval = self.get_constant().get_value()
        return self.xd.vd.app.stringxrefs.get_string(str(hex(xval)))

    def get_constant(self): return self.xd.get_numerical(int(self.args[0]))

    def __str__(self):
        if (self.is_string_reference()
                and len(self.get_string_reference()) > 1):
            strvalue = '"' + self.get_string_reference() + '"'
            return strvalue
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
    def is_stack_base_address(self): return False
    def is_stack_address(self): return False

    def is_true(self): return False
    def is_false(self): return False

    # returns true if this expression is a dereference
    def is_structured_expr(self): return False

    # returns true if this expression is a constant string
    def is_string_reference(self):
        return self.is_const() and self.get_const().is_string_reference()

    # returns true if this expression is an expression involving the stack pointer
    def is_stack_address(self): return False

    # returns a dictionary gv -> count
    def get_global_variables(self): return {}

    # returns the terms in the expression
    def get_terms(self): return [ self ]

    # returns the factors in the expression
    def get_factors(self): return [ self ]

    # returns true if this expression is a string-manipulation condition
    def is_string_manipulation_condition(self): return False

    # returns an InputConstraint object if conversion is successful
    def to_input_constraint(self): return None
    def to_input_constraint_value(self): return None

    # returns a dictionary containing value and meta information
    def to_annotated_value(self):
        return { 'v': str(self) }

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

    def is_function_return_value(self):
        return (self.get_variable().has_denotation()
                    and self.get_variable().get_denotation().is_function_return_value())

    def is_argument_deref_value(self):
        if (self.get_variable().has_denotation()
            and self.get_variable().get_denotation().is_initial_memory_value()):
            auxvar = self.get_variable().get_denotation().get_auxiliary_variable()
            return auxvar.is_argument_deref_value()
        return False

    def is_command_line_argument_value(self):
        if self.is_argument_deref_value():
            auxvar = self.get_variable().get_denotation().get_auxiliary_variable()
            (arg,offset) = auxvar.get_argument_deref_arg_offset()
            return arg == 2
        return False

    def is_stack_base_address(self):
        if self.get_variable().has_denotation():
            return self.get_variable().get_dentation().is_stack_base_address()

    def get_command_line_argument_value_index(self):
        if self.is_command_line_argument_value():
            auxvar = self.get_variable().get_denotation().get_auxiliary_variable()
            (arg,offset) = auxvar.get_argument_deref_arg_offset()
            return offset

    def get_returnval_target(self):
        if self.is_function_return_value():
            xaux = self.get_variable().get_denotation().get_auxiliary_variable()
            if xaux.has_call_target():
                return str(xaux.get_call_target())

    def get_returnval_arguments(self):
        if self.is_function_return_value():
            xaux  = self.get_variable().get_denotation().get_auxiliary_variable()
            return xaux.get_call_arguments()

    def to_input_constraint_value(self):
        if self.is_function_return_value():
            tgt = self.get_returnval_target()
            if tgt is None:
                return
            if tgt == 'getenv':
                envarg = self.get_returnval_arguments()[0]
                return IC.EnvironmentInputValue(str(envarg))
            if tgt in [ 'strchr', 'strrchr' ]:
                strk = self.get_returnval_arguments()[0].to_input_constraint_value()
                if not strk is None:
                    cchar = self.get_returnval_arguments()[1]
                    charval = cchar.get_const().get_constant().get_value()
                    charcode = "'" + chr(charval) + "'"
                    return IC.StringSuffixValue(strk,charcode,lastpos=(tgt == 'strrchr'))
        elif self.is_command_line_argument_value():
            argindex = self.get_command_line_argument_value_index()
            return IC.CommandLineArgument(argindex)

    def to_annotated_value(self):
        result = BXXprBase.to_annotated_value(self)
        if self.is_function_return_value():
            result['k'] = 'sc:rv'
            result['c'] = str(self.get_returnval_target())
            callee_args = self.get_returnval_arguments()
            if callee_args:
                result['args'] = [ a.to_annotated_value() for a in self.get_returnval_arguments() ]
        return result

    def __str__(self):
        if self.is_function_return_value():
            tgtval = self.get_returnval_target()
            if tgtval:
                return 'rtn_' + tgtval
        return str(self.get_variable())

class BXConst(BXXprBase):

    def __init__(self,xd,index,tags,args):
        BXXprBase.__init__(self,xd,index,tags,args)

    def is_const(self): return True

    def is_int_const_value(self,n):
        return (self.get_const().is_intconst()
                    and self.get_const().get_constant().get_value() == n)

    def is_zero(self): return self.is_int_const_value(0)

    def is_boolconst(self): return self.get_const().is_boolconst()

    def is_false(self):
        return self.is_boolconst() and self.get_const().is_false()

    def is_true(self):
        return self.is_boolconst() and self.get_const().is_true()

    def get_negated_value(self):
        return -(self.get_const().get_constant().get_value())

    def get_const(self): return self.xd.get_xcst(int(self.args[0]))

    def get_constant_value(self): return self.get_const().get_constant().get_value()

    def to_annotated_value(self):
        result = BXXprBase.to_annotated_value(self)
        result['k'] = 'c'
        const = self.get_const()
        if const.is_string_reference():
            result['t'] = 's'
        elif const.is_intconst():
            result['t'] = 'i'
        return result


    def __str__(self): return str(self.get_const())

class BXOp(BXXprBase):

    def __init__(self,xd,index,tags,args):
        BXXprBase.__init__(self,xd,index,tags,args)

    def is_op(self): return True

    def get_terms(self):
        result = []
        if self.get_op() == 'plus':
            for a in self.get_args():
                if a.is_op():
                    result.extend(a.get_terms())
                else:
                    result.append(a)
            else: pass
        else:
            result.append(self)
        return result

    def get_factors(self):
        result = []
        if self.get_op() == 'mult':
            for a in self.get_args():
                if a.is_op():
                    result.extend(a.get_factors())
                else:
                    result.append(a)
            else: pass
        else:
            result.append(self)
        return result

    def is_structured_expr(self):
        return any([ arg.is_structured_expr() for arg in self.get_args() ])

    def is_stack_address(self):
        args = self.get_args()
        if len(args) == 2:
            return (args[0].is_stack_base_address and args[1].is_const())

    def get_stack_address_offset(self):
        if self.is_stack_address():
            stackoffset = self.get_args()[1]
            if self.get_op() == 'minus':
                return stackoffset.get_negated_value()
            else:
                return stackoffset.get_constant_value()
        else:
            raise UF.CHBError('Expression is not a stack address')

    def is_string_manipulation_condition(self):
        string_manipulation_functions = [
            'strcmp', 'strncmp', 'strchr', 'strrchr', 'strcasecmp', 'strstr',
            'strncasecmp' ]
        args = self.get_args()
        if self.get_args()[0].is_var():
            xvar = args[0].get_variable()
            if xvar.has_denotation():
                xden = xvar.get_denotation()
                if xden.is_function_return_value():
                    xaux = xden.get_auxiliary_variable()
                    if xaux.has_call_target():
                        tgt = xaux.get_call_target()
                        return str(tgt) in string_manipulation_functions
        return False

    def is_returnval_comparison(self):
        """Returns true if the first argument of a comparison is a function return value."""
        args = self.get_args()
        return (args[0].is_var()
                    and args[0].is_function_return_value()
                    and self.get_op() in [ 'eq', 'ne' ])

    def is_returnval_arithmetic_expr(self):
        """Returns true if the first argument of an arithmetic expression is a return value."""
        args = self.get_args()
        return (args[0].is_var()
                    and args[0].is_function_return_value()
                    and self.get_op() in [ 'plus', 'minus' ])

    def get_returnval_comparison_target(self):
        if self.is_returnval_comparison():
            return self.get_args()[0].get_returnval_target()

    def get_returnval_comparison_arguments(self):
        if self.is_returnval_comparison():
            return self.get_args()[0].get_returnval_arguments()

    def to_input_constraint_value(self):
        if self.is_returnval_arithmetic_expr():
            arg1 = self.get_args()[0].to_input_constraint_value()
            if not arg1 is None and self.get_args()[1].is_const():
                return IC.InputConstraintValueExpr(xpr_operator_strings[self.get_op()],
                                                       arg1,
                                                       str(self.get_args()[1]))

    def to_input_constraint(self):
        if self.is_returnval_comparison():
            tgt = self.get_returnval_comparison_target()
            if tgt == 'getenv':
                if self.get_op() == 'ne' and self.get_args()[1].is_zero():
                    envarg = self.get_returnval_comparison_arguments()[0]
                    return IC.EnvironmentTestConstraint(str(envarg))
                elif self.get_op() == 'eq' and self.get_args()[1].is_zero():
                    envarg  = self.get_returnval_comparison_arguments()[0]
                    return IC.EnvironmentAbsentConstraint(str(envarg))
            if tgt in [ 'strncmp', 'strncasecmp' ]:
                callargs = self.get_returnval_comparison_arguments()
                cstr = callargs[1]
                argk = callargs[0].to_input_constraint_value()
                if not argk is None:
                    if self.get_op() == 'eq' and self.get_args()[1].is_zero():
                        return IC.StringStartsWithConstraint(argk,cstr)
                    elif self.get_op() == 'ne' and self.get_args()[1].is_zero():
                        return IC.StringNotStartsWithConstraint(argk,cstr)
            if tgt in [ 'strcmp', 'strcasecmp' ]:
                callargs = self.get_returnval_comparison_arguments()
                cstr = callargs[1]
                argk = callargs[0]
                if not argk is None:
                    if self.get_op() == 'eq' and self.get_args()[1].is_zero():
                        return IC.StringEqualsConstraint(argk,cstr,
                                                             case_insensitive=(tgt =='strcasecmp'))
                    elif self.get_op() == 'ne' and self.get_args()[1].is_zero():
                        return IC.StringNotEqualsConstraint(argk,cstr,
                                                                case_insensitive=(tgt=='strcasecmp'))
            if tgt in [ 'memcmp' ]:
                callargs = self.get_returnval_comparison_arguments()
                cbytes = callargs[1]
                argk = callargs[0]
                clen = callargs[2]
                if not argk is None:
                    if self.get_op() == 'eq' and self.get_args()[1].is_zero():
                        return IC.StringStartsWithConstraint(argk,cbytes)
                    elif self.get_op() == 'ne' and self.get_args()[1].is_zero():
                        return IC.StringNotStartsWithConstraint(argk,cbytes)
            if tgt in [ 'strstr', 'stristr']:
                callargs = self.get_returnval_comparison_arguments()
                cvar = callargs[0]
                cstr = callargs[1]
                argk = callargs[0]
                if not argk is None:
                    if self.get_op() == 'ne' and self.get_args()[1].is_zero():
                        return IC.StringContainsConstraint(argk,cstr)
                    elif self.get_op() == 'eq' and self.get_args()[1].is_zero():
                        return IC.StringNotContainsConstraint(argk,cstr)
            if tgt in [ 'strchr', 'strrchr' ]:
                callargs = self.get_returnval_comparison_arguments()
                argk = callargs[0].to_input_constraint_value()
                cchar = callargs[1]
                if argk is not None and cchar.is_const():
                    charval = cchar.get_const().get_constant().get_value()
                    charcode = "'" + chr(charval) + "'"
                    if self.get_op() == 'eq' and self.get_args()[1].is_zero():
                        return IC.StringNotContainsConstraint(argk,str(charcode))
                    elif self.get_op() == 'ne' and self.get_args()[1].is_zero():
                        return IC.StringContainsConstraint(argk,str(charcode))


    def string_condition_to_pretty(self):
        if self.is_string_manipulation_condition():
            arg0 = self.get_args()[0]
            xden = arg0.get_variable().get_denotation().get_auxiliary_variable()
            xtgt = str(xden.get_call_target())
            if xtgt == 'strcmp' or xtgt  == 'strcasecmp' or xtgt == 'strncmp':
                callargs = xden.get_call_arguments()
                cvar = callargs[0]
                cstr = callargs[1]
                if self.get_op() == 'eq':
                    return str(cvar) + ' = ' + str(cstr)
                else:
                    return str(cvar) + ' != ' + str(cstr)
            if xtgt == 'strrchr' or xtgt == 'strchr':
                callargs = xden.get_call_arguments()
                cxpr = callargs[0]
                cchar = callargs[1]
                if cchar.is_const():
                    charval = cchar.get_const().get_constant().get_value()
                    charcode = chr(charval)
                    if self.get_op() == 'eq':
                        return "'" + str(charcode) + "'" + ' not in ' + str(cxpr)
                    else:
                        return "'" + str(charcode) + "'" + ' in ' + str(cxpr)
            if xtgt == 'strstr':
                callargs = xden.get_call_arguments()
                cxpr = callargs[0]
                cstr = callargs[1]
                if self.get_op() == 'eq':
                    return "'" + str(cstr) + "'" + ' not in ' + str(cxpr)
                else:
                    return "'" + str(cstr) + "'" + ' in ' + str(cxpr)
        return str(self)


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

    def to_annotated_value(self):
        result = BXXprBase.to_annotated_value(self)
        result['k'] = 'x'
        result['op'] = self.get_op()
        result['args'] = [ a.to_annotated_value() for a in self.get_args() ]
        return result

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
