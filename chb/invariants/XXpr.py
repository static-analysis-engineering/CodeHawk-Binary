# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny B. Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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
"""Expression over CHIF variables.

Corresponds to xpr_t in xprlib/xprTypes:

                                   tags[0]   tags   args
type xpr_t =
  | XVar of variable_t               "v"       1      1
  | XConst of xcst_t                 "c"       1      1
  | XOp of xop_t * xpr_t list        "x"       2    list length
  | XAttr of string * xpr_t          "a"       2      1

"""
from typing import (
    Any, cast, Dict, List, Mapping, Optional, Sequence, TYPE_CHECKING)

from chb.api.CallTarget import CallTarget

from chb.app.Register import Register

from chb.invariants.FnDictionaryRecord import FnXprDictionaryRecord, xprregistry

import chb.invariants.InputConstraint as IC
import chb.invariants.InputConstraintValue as ICV

from chb.invariants.XConstant import XConstant, XBoolConst
from chb.invariants.XVariable import XVariable

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnXprDictionary import FnXprDictionary


xpr_operator_strings = {
    "": " % ",
    "band": " & ",
    "bor": " | ",
    "bxor": " xor ",
    "bnor": " bnor ",
    "bnot": " ~",
    "div": " / ",
    "eq": " == ",
    "ge": " >= ",
    "gt": " > ",
    "le": " <= ",
    "lor": " || ",
    "land": " && ",
    "lnot": "!",
    "lt": " < ",
    "minus": " - ",
    "mod": " % ",
    "mult": " * ",
    "ne": " != ",
    "neg": " -",
    "plus": " + ",
    "range": " range ",
    "shiftlt": " << ",
    "shiftrt": " >> ",
    "lsr": " >> ",
    "asr": " s>> ",
    "lsl": " << ",
    "lsb": "lsb ",
    "lsh": "lsh ",
    "xbyte": " xbyte "
}


class XXpr(FnXprDictionaryRecord):
    """Analysis base expression."""

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        FnXprDictionaryRecord.__init__(self, xd, ixval)

    @property
    def is_var(self) -> bool:
        return False

    @property
    def is_register_variable(self) -> bool:
        return False

    @property
    def is_initial_register_value(self) -> bool:
        """Return true if this expression is the initial value of a register."""

        return False

    @property
    def is_tmp_variable(self) -> bool:
        return False

    def has_unknown_memory_base(self) -> bool:
        """Return true if this expression is a memory variable with unknown base."""

        return False

    @property
    def is_constant(self) -> bool:
        return False

    @property
    def is_constant_value_variable(self) -> bool:
        return False

    @property
    def is_int_constant(self) -> bool:
        return False

    @property
    def is_global_address(self) -> bool:
        return False

    @property
    def is_global_variable(self) -> bool:
        return False

    def is_int_const_value(self, n: int) -> bool:
        return False

    @property
    def is_compound(self) -> bool:
        return False

    @property
    def is_attr(self) -> bool:
        return False

    @property
    def is_four_multiple(self) -> bool:
        return False

    @property
    def is_memory_address_value(self) -> bool:
        return False

    @property
    def is_stack_base_address(self) -> bool:
        return False

    @property
    def is_heap_base_address(self) -> bool:
        return False

    @property
    def is_argument_value(self) -> bool:
        return False

    def argument_index(self) -> int:
        if self.is_argument_value:
            return self.variable.denotation.argument_index()
        else:
            raise UF.CHBError("Xpr is not an argument value: " + str(self))

    @property
    def is_true(self) -> bool:
        return False

    @property
    def is_false(self) -> bool:
        return False

    @property
    def is_zero(self) -> bool:
        raise UF.CHBError("Is_zero is not supported for " + str(self))

    @property
    def is_structured_expr(self) -> bool:
        """Returns true if this expression is a dereference."""
        return False

    @property
    def is_string_reference(self) -> bool:
        """Returns true is this expression is a constant string."""
        return False

    @property
    def is_stack_address(self) -> bool:
        """Returns true if this expression involves the stack pointer."""
        return False

    def stack_address_offset(self) -> int:
        raise UF.CHBError(
            "Expression is not a stack address with stack address offset")

    def initial_register_value_register(self) -> Register:
        """Returns the register of which this expression represents the initial value."""
        raise UF.CHBError(
            "Expression is not an initial register value")

    @property
    def is_heap_address(self) -> bool:
        return self.is_heap_base_address

    @property
    def is_function_return_value(self) -> bool:
        return False

    @property
    def is_symbolic_expr_value(self) -> bool:
        return False

    @property
    def constant(self) -> XConstant:
        raise UF.CHBError("Constant property not supported for " + str(self))

    @property
    def intvalue(self) -> int:
        raise UF.CHBError("Intvalue property not supported for " + str(self))

    @property
    def is_string_manipulation_condition(self) -> bool:
        """Returns true if this expression manipulates strings."""
        return False

    @property
    def is_register_comparison(self) -> bool:
        """Returns true if this is a comparison that only involves registers."""
        return False

    @property
    def variable(self) -> XVariable:
        raise UF.CHBError(
            "Expression does not have a variable property: " + str(self))

    def returnval_target(self) -> CallTarget:
        raise UF.CHBError("Get_returnval_target not supported for " + str(self))

    def returnval_arguments(self) -> Sequence["XXpr"]:
        raise UF.CHBError("Get_returnval_arguments not supported for " + str(self))

    def global_variables(self) -> Mapping[str, int]:
        """Returns a dictionary with a count for each global variable."""
        raise UF.CHBError("Get_global_variables not supported for " + str(self))

    def has_global_variables(self) -> bool:
        return False

    def has_global_references(self) -> bool:
        return False

    def negated_value(self) -> int:
        raise UF.CHBError("Get_negated_value not supported for " + str(self))

    def terms(self) -> Sequence["XXpr"]:
        """Returns the terms in this expression."""
        return [self]

    def factors(self) -> Sequence["XXpr"]:
        """Returns the factors in this expression."""
        return [self]

    def variables(self) -> Sequence[XVariable]:
        """Returns the variables in this expressions."""
        return []

    def to_input_constraint(self) -> Optional[IC.InputConstraint]:
        """Returns an input constraint if this expression can be converted."""
        return None

    def to_input_constraint_value(self) -> Optional[ICV.InputConstraintValue]:
        """Returns an input constraint value if this expression can be converted."""
        return None

    def to_annotated_value(self) -> Dict[str, Any]:
        """Returns a dictionary containing value and meta information."""
        return {'v': str(self)}

    def to_json_result(self) -> JSONResult:
        return JSONResult(
            "xexpression",
            {},
            "fail",
            "xexpression: not yet implemented (" + self.tags[0] + ")")

    def __str__(self) -> str:
        return 'basexpr:' + self.tags[0]


@xprregistry.register_tag("v", XXpr)
class XprVariable(XXpr):
    """CHIF variable in expression.

    args[0]: index in xd of CHIF variable
    """

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XXpr.__init__(self, xd, ixval)

    @property
    def variable(self) -> XVariable:
        return self.xd.variable(self.args[0])

    @property
    def is_constant_value_variable(self) -> bool:
        return self.variable.is_constant_value_variable

    @property
    def is_register_variable(self) -> bool:
        return self.variable.is_register_variable

    @property
    def is_initial_register_value(self) -> bool:
        return self.variable.is_initial_register_value

    @property
    def is_var(self) -> bool:
        return True

    @property
    def is_memory_address_value(self) -> bool:
        return self.variable.is_memory_address_value

    @property
    def is_tmp_variable(self) -> bool:
        return self.variable.is_tmp

    def has_unknown_memory_base(self) -> bool:
        return self.variable.has_unknown_memory_base()

    @property
    def is_structured_expr(self) -> bool:
        return self.variable.is_structured_var

    @property
    def is_global_variable(self) -> bool:
        return self.variable.is_global_variable

    @property
    def is_function_return_value(self) -> bool:
        return (self.variable.has_denotation()
                and self.variable.denotation.is_function_return_value)

    @property
    def is_argument_value(self) -> bool:
        return (self.variable.has_denotation()
                and self.variable.is_argument_value)

    @property
    def is_argument_deref_value(self) -> bool:
        return (self.variable.has_denotation()
                and self.variable.is_argument_deref_value)

    @property
    def is_command_line_argument_value(self) -> bool:
        if self.is_argument_deref_value:
            (arg, offset) = self.variable.denotation.argument_deref_arg_offset()
            return arg == 2
        else:
            return False

    @property
    def is_stack_base_address(self) -> bool:
        if self.variable.has_denotation():
            return self.variable.denotation.is_stack_base_address
        else:
            return False

    @property
    def is_heap_base_address(self) -> bool:
        if self.variable.has_denotation():
            return self.variable.denotation.is_heap_base_address
        else:
            return False

    @property
    def is_symbolic_expr_value(self) -> bool:
        if self.variable.has_denotation():
            return self.variable.denotation.is_symbolic_expr_value
        else:
            return False

    def global_variables(self) -> Mapping[str, int]:
        result: Dict[str, int] = {}
        if self.is_global_variable:
            result[str(self.variable.global_variable_base())] = 1
        return result

    def has_global_variables(self) -> bool:
        return len(self.global_variables()) > 0

    def has_global_references(self) -> bool:
        return self.has_global_variables()

    def argument_index(self) -> int:
        if self.is_argument_value:
            return self.variable.denotation.argument_index()
        else:
            raise UF.CHBError("Xpr is not an argument value: " + str(self))

    def initial_register_value_register(self) -> Register:
        return self.variable.initial_register_value_register()

    def command_line_argument_value_index(self) -> int:
        if self.is_command_line_argument_value:
            (arg, offset) = self.variable.denotation.argument_deref_arg_offset()
            return offset
        else:
            raise UF.CHBError("Variable is not a command-line argument: "
                              + str(self))

    def returnval_target(self) -> CallTarget:
        if self.is_function_return_value:
            xaux = self.variable.denotation.auxvar
            if xaux.has_call_target():
                return xaux.call_target()
            else:
                raise UF.CHBError("Constant value variable has no call target: "
                                  + str(self))
        else:
            raise UF.CHBError("Expression is not a function-return-value: "
                              + str(self))

    def returnval_arguments(self) -> Sequence["XXpr"]:
        if self.is_function_return_value:
            return self.variable.denotation.call_arguments()
        else:
            raise UF.CHBError("Expression is not a return value: " + str(self))

    def to_input_constraint_value(self) -> Optional[ICV.InputConstraintValue]:
        if self.is_argument_value:
            argindex = self.variable.denotation.auxvar.argument_index()
            return ICV.FunctionArgumentValue(argindex)
        if self.is_function_return_value:
            tgt = self.returnval_target()
            if tgt is None:
                return None
            if tgt == 'getenv':
                envarg = self.returnval_arguments()[0]
                return ICV.EnvironmentInputValue(str(envarg))
            if tgt in ['strchr', 'strrchr']:
                strk = self.returnval_arguments()[0].to_input_constraint_value()
                if strk is not None:
                    cchar = self.returnval_arguments()[1]
                    if cchar.is_constant:
                        charval = cchar.constant.value
                        charcode = "'" + chr(charval) + "'"
                        return ICV.StringSuffixValue(
                            strk, charcode, lastpos=(tgt == 'strrchr'))
                    else:
                        return None
                else:
                    return None
            else:
                return None
        elif self.is_command_line_argument_value:
            argindex = self.command_line_argument_value_index()
            return ICV.CommandLineArgument(argindex)
        else:
            return None

    def to_annotated_value(self) -> Dict[str, Any]:
        result = XXpr.to_annotated_value(self)
        if self.is_function_return_value:
            result['k'] = 'sc:rv'
            result['c'] = str(self.returnval_target())
            callee_args = self.returnval_arguments()
            if callee_args:
                result["args"] = [
                    a.to_annotated_value() for a in self.returnval_arguments()]
        return result

    def variables(self) -> Sequence[XVariable]:
        return [self.variable]

    def to_json_result(self) -> JSONResult:
        jvar = self.variable.to_json_result()
        if jvar.is_ok:
            content: Dict[str, Any] = {}
            content["kind"] = "xvar"
            content["var"] = jvar.content
            content["txtrep"] = str(self)
            return JSONResult("xexpression", content, "ok")
        else:
            return JSONResult(
                "xexpression",
                {},
                "fail",
                "xexpression: " + str(jvar.reason))

    @staticmethod
    def mk_instance(xd: "FnXprDictionary", varix: int) -> "XXpr":
        index = xd.index_xpr(["v"], [varix])
        return xd.xpr(index)

    def __str__(self) -> str:
        return str(self.variable)


@xprregistry.register_tag("c", XXpr)
class XprConstant(XXpr):

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XXpr.__init__(self, xd, ixval)

    @property
    def constant(self) -> XConstant:
        return self.xd.xcst(self.args[0])

    @property
    def intvalue(self) -> int:
        if self.is_int_constant:
            return self.constant.value
        else:
            raise UF.CHBError(
                "Constant is not an integer constant: " + str(self))

    @property
    def is_constant(self) -> bool:
        return True

    @property
    def is_int_constant(self) -> bool:
        return self.constant.is_int_constant

    @property
    def is_bool_constant(self) -> bool:
        return self.constant.is_boolconst

    @property
    def is_string_reference(self) -> bool:
        return self.constant.is_string_reference

    @property
    def is_global_address(self) -> bool:
        return self.constant.is_global_address

    def has_global_references(self) -> bool:
        return self.is_global_address

    def is_int_const_value(self, n: int) -> bool:
        return (self.is_int_constant and self.intvalue == n)

    @property
    def is_zero(self) -> bool:
        return self.is_int_const_value(0)

    @property
    def is_boolconst(self) -> bool:
        return self.constant.is_boolconst

    @property
    def is_random_constant(self) -> bool:
        return self.constant.is_random

    @property
    def is_false(self) -> bool:
        if self.is_boolconst:
            c = cast(XBoolConst, self.constant)
            return c.is_false
        else:
            raise UF.CHBError("Not a boolean constant: " + str(self))

    @property
    def is_true(self) -> bool:
        if self.is_boolconst:
            c = cast(XBoolConst, self.constant)
            return c.is_true
        else:
            raise UF.CHBError("Not a boolean constant: " + str(self))

    def negated_value(self) -> int:
        if self.is_int_constant:
            return -(self.constant.value)
        else:
            raise UF.CHBError("Constant is not an integer constant: " + str(self))

    def to_annotated_value(self) -> Dict[str, Any]:
        result = XXpr.to_annotated_value(self)
        result['k'] = 'c'
        const = self.constant
        if const.is_string_reference:
            result['t'] = 's'
        elif const.is_intconst:
            result['t'] = 'i'
        return result

    def to_json_result(self) -> JSONResult:
        jcst = self.constant.to_json_result()
        if not jcst.is_ok:
            return JSONResult(
                "xexpression",
                {},
                "fail",
                "xexpression: " + str(jcst.reason))
        content: Dict[str, Any] = {}
        content["kind"] = "xcst"
        content["cst"] = jcst.content
        content["txtrep"] = str(self)
        return JSONResult("xexpression", content, "ok")

    @staticmethod
    def mk_instance(xd: "FnXprDictionary", cstix: int) -> "XXpr":
        index = xd.index_xpr(["c"], [cstix])
        return xd.xpr(index)

    def __str__(self) -> str:
        return str(self.constant)


@xprregistry.register_tag("x", XXpr)
class XprCompound(XXpr):
    """Compound expression.

    tags[1]: operator
    args[0..]: indices of operands in xd
    """

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XXpr.__init__(self, xd, ixval)
        self._terms: List[XXpr] = []
        self._factors: List[XXpr] = []

    @property
    def is_compound(self) -> bool:
        return True

    @property
    def operator(self) -> str:
        return self.tags[1]

    @property
    def operands(self) -> Sequence[XXpr]:
        return [self.xd.xpr(i) for i in self.args]

    def terms(self) -> Sequence[XXpr]:
        if len(self._terms) == 0:
            if self.operator == "plus":
                for a in self.operands:
                    if a.is_compound:
                        self._terms.extend(a.terms())
                    else:
                        self._terms.append(a)
                else:
                    pass
            else:
                self._terms.append(self)
        return self._terms

    def factors(self) -> Sequence[XXpr]:
        if len(self._factors) == 0:
            if self.operator == "mult":
                for a in self.operands:
                    if a.is_compound:
                        self._factors.extend(a.factors())
                    else:
                        self._factors.append(a)
                else:
                    pass
            else:
                self._factors.append(self)
        return self._factors

    @property
    def is_structured_expr(self) -> bool:
        return any([op.is_structured_expr for op in self.operands])

    def has_global_variables(self) -> bool:
        return any([op.has_global_variables() for op in self.operands])

    def has_global_references(self) -> bool:
        return any([op.has_global_references() for op in self.operands])

    @property
    def is_stack_address(self) -> bool:
        args = self.operands
        if len(args) == 2:
            return (args[0].is_stack_base_address and args[1].is_constant)
        else:
            return False

    def stack_address_offset(self) -> int:
        if self.is_stack_address:
            stackoffset = self.operands[1]
            if self.operator == 'minus':
                return stackoffset.negated_value()
            else:
                return stackoffset.intvalue
        else:
            raise UF.CHBError(
                "Expression is not a stack address: " + str(self))

    @property
    def is_heap_address(self) -> bool:
        args = self.operands
        if len(args) == 2:
            return (args[0].is_heap_base_address and args[1].is_constant)
        else:
            return False

    @property
    def is_string_manipulation_condition(self) -> bool:
        string_manipulation_functions = [
            'strcmp', 'strncmp', 'strchr', 'strrchr', 'strcasecmp', 'strstr',
            'strncasecmp']
        args = self.operands
        if self.operands[0].is_var:
            xvar = args[0].variable
            if xvar.has_denotation():
                xden = xvar.denotation
                if xden.is_function_return_value:
                    xaux = xden.auxvar
                    if xaux.has_call_target():
                        tgt = xaux.call_target()
                        return str(tgt) in string_manipulation_functions
        return False

    @property
    def is_returnval_comparison(self) -> bool:
        """Returns true if the first argument of a comparison is a return value."""

        args = self.operands
        return (
            args[0].is_var
            and args[0].is_function_return_value
            and self.operator in ["eq", "ne"])

    @property
    def is_register_comparison(self) -> bool:
        """Return true if this is a comparison that involves only registers."""

        args = self.operands
        return (
            (args[0].is_register_variable or args[0].is_constant)
            and (args[1].is_register_variable or args[1].is_constant)
            and self.operator in ["eq", "le", "ge", "lt", "gt", "ne"])

    @property
    def is_returnval_arithmetic_expr(self) -> bool:
        """Returns true if the first argument of an expression is a return value."""

        args = self.operands
        return (args[0].is_var
                and args[0].is_function_return_value
                and self.operator in ["plus", "minus"])

    def returnval_comparison_target(self) -> CallTarget:
        if self.is_returnval_comparison:
            return self.operands[0].returnval_target()
        else:
            raise UF.CHBError(
                "Expression is not a returnval comparison: " + str(self))

    def returnval_comparison_arguments(self) -> Sequence[XXpr]:
        if self.is_returnval_comparison:
            return self.operands[0].returnval_arguments()
        else:
            return []

    def to_input_constraint_value(self) -> Optional[ICV.InputConstraintValue]:
        if self.is_returnval_arithmetic_expr:
            arg1 = self.operands[0].to_input_constraint_value()
            if arg1 is not None and self.operands[1].is_constant:
                return ICV.InputConstraintValueExpr(
                    xpr_operator_strings[self.operator],
                    arg1,
                    str(self.operands[1]))
            else:
                return None
        else:
            return None

    def to_input_constraint(self) -> Optional[IC.InputConstraint]:
        if self.is_returnval_comparison:
            tgt = str(self.returnval_comparison_target())
            if tgt == 'getenv':
                if self.operator == 'ne' and self.operands[1].is_zero:
                    envarg = self.returnval_comparison_arguments()[0]
                    return IC.EnvironmentTestConstraint(str(envarg))
                elif self.operator == 'eq' and self.operands[1].is_zero:
                    envarg = self.returnval_comparison_arguments()[0]
                    return IC.EnvironmentAbsentConstraint(str(envarg))
            elif tgt in ['strncmp', 'strncasecmp']:
                callargs = self.returnval_comparison_arguments()
                cstr = callargs[1]
                argk = callargs[0].to_input_constraint_value()
                if argk is not None:
                    if self.operator == 'eq' and self.operands[1].is_zero:
                        return IC.StringStartsWithConstraint(argk, cstr)
                    elif self.operator == 'ne' and self.operands[1].is_zero:
                        return IC.StringNotStartsWithConstraint(argk, cstr)
            elif tgt in ['strcmp', 'strcasecmp']:
                callargs = self.returnval_comparison_arguments()
                cstr = callargs[1]
                argk = callargs[0].to_input_constraint_value()
                if argk is not None:
                    if self.operator == 'eq' and self.operands[1].is_zero:
                        return IC.StringEqualsConstraint(
                            argk, cstr, case_insensitive=(tgt == 'strcasecmp'))
                    elif self.operator == 'ne' and self.operands[1].is_zero:
                        return IC.StringNotEqualsConstraint(
                            argk, cstr, case_insensitive=(tgt == 'strcasecmp'))
            elif tgt in ['memcmp']:
                callargs = self.returnval_comparison_arguments()
                cbytes = callargs[1]
                argk = callargs[0].to_input_constraint_value()
                clen = callargs[2]
                if argk is not None:
                    if self.operator == 'eq' and self.operands[1].is_zero:
                        return IC.StringStartsWithConstraint(argk, cbytes)
                    elif self.operator == 'ne' and self.operands[1].is_zero:
                        return IC.StringNotStartsWithConstraint(argk, cbytes)
            elif tgt in ['strstr', 'stristr']:
                callargs = self.returnval_comparison_arguments()
                cvar = callargs[0]
                cstr = callargs[1]
                argk = callargs[0].to_input_constraint_value()
                if argk is not None:
                    if self.operator == 'ne' and self.operands[1].is_zero:
                        return IC.StringContainsConstraint(argk, str(cstr))
                    elif self.operator == 'eq' and self.operands[1].is_zero:
                        return IC.StringNotContainsConstraint(argk, str(cstr))
            elif tgt in ['strchr', 'strrchr']:
                callargs = self.returnval_comparison_arguments()
                argk = callargs[0].to_input_constraint_value()
                cchar = callargs[1]
                if argk is not None and cchar.is_constant:
                    charval = cchar.intvalue
                    charcode = "'" + chr(charval) + "'"
                    if self.operator == 'eq' and self.operands[1].is_zero:
                        return IC.StringNotContainsConstraint(argk, str(charcode))
                    elif self.operator == 'ne' and self.operands[1].is_zero:
                        return IC.StringContainsConstraint(argk, str(charcode))
        return None

    def string_condition_to_pretty(self) -> str:
        if self.is_string_manipulation_condition:
            arg0 = self.operands[0]
            xden = arg0.variable.denotation.auxvar
            xtgt = str(xden.call_target())
            if xtgt == 'strcmp' or xtgt == 'strcasecmp' or xtgt == 'strncmp':
                callargs = xden.call_arguments()
                cvar = callargs[0]
                cstr = callargs[1]
                if self.operator == 'eq':
                    return str(cvar) + ' = ' + str(cstr)
                else:
                    return str(cvar) + ' != ' + str(cstr)
            if xtgt == 'strrchr' or xtgt == 'strchr':
                callargs = xden.call_arguments()
                cxpr = callargs[0]
                cchar = callargs[1]
                if cchar.is_constant:
                    charval = cchar.intvalue
                    charcode = chr(charval)
                    if self.operator == 'eq':
                        return "'" + str(charcode) + "'" + ' not in ' + str(cxpr)
                    else:
                        return "'" + str(charcode) + "'" + ' in ' + str(cxpr)
            if xtgt == 'strstr':
                callargs = xden.call_arguments()
                cxpr = callargs[0]
                cstr = callargs[1]
                if self.operator == 'eq':
                    return "'" + str(cstr) + "'" + ' not in ' + str(cxpr)
                else:
                    return "'" + str(cstr) + "'" + ' in ' + str(cxpr)
        return str(self)

    @property
    def is_lsb(self) -> bool:
        return self.operator == "lsb"

    def lsb_operand(self) -> XXpr:
        if self.operator == "lsb":
            return self.operands[0]
        else:
            raise UF.CHBError("Expression is not an lsb operation")

    @property
    def is_four_multiple(self) -> bool:
        if self.operator == 'mult':
            args = self.operands
            if len(args) == 2:
                arg1 = args[0]
                arg2 = args[1]
                return ((
                    arg1.is_constant
                    and arg1.is_int_const_value(4))
                        or (arg2.is_constant and arg2.is_int_const_value(4)))
        return False

    def quotient_four(self) -> XXpr:
        if self.is_four_multiple:
            args = self.operands
            arg1 = args[0]
            arg2 = args[1]
            if arg1.is_constant and arg1.is_int_const_value(4):
                return arg2
            else:
                return arg1
        else:
            raise UF.CHBError("Expression is not a multiple of four: " + str(self))

    def to_annotated_value(self) -> Dict[str, Any]:
        result = XXpr.to_annotated_value(self)
        result['k'] = 'x'
        result['op'] = self.operator
        result['args'] = [a.to_annotated_value() for a in self.operands]
        return result

    def variables(self) -> Sequence[XVariable]:
        result: List[XVariable] = []
        for op in self.operands:
            result.extend(op.variables())
        return result

    def to_json_result(self) -> JSONResult:
        jops: List[Dict[str, Any]] = []
        for opr in self.operands:
            jopr = opr.to_json_result()
            if not jopr.is_ok:
                return JSONResult(
                    "xexpression",
                    {},
                    "fail",
                    "xexpression: " + str(jopr.reason))
            jops.append(jopr.content)
        content: Dict[str, Any] = {}
        content["kind"] = "xop"
        content["operator"] = self.operator
        content["operands"] = jops
        content["txtrep"] = str(self)
        return JSONResult("xexpression", content, "ok")

    @staticmethod
    def mk_instance(xd: "FnXprDictionary", op: str, args: List[int]) -> "XXpr":
        index = xd.index_xpr(["x", op], args)
        return xd.xpr(index)

    def __str__(self) -> str:
        args = self.operands
        if len(args) == 1:
            if self.operator in xpr_operator_strings:
                return (
                    "(" + xpr_operator_strings[self.operator] + str(args[0]) + ")")
            else:
                return "(" + self.operator + " " + str(args[0]) + ")"
        elif len(args) == 2:
            return (
                '('
                + str(args[0])
                + xpr_operator_strings[self.operator]
                + str(args[1])
                + ')')
        else:
            return (
                '('
                + xpr_operator_strings[self.operator]
                + '('
                + ','.join(str(x) for x in args)
                + ')')


@xprregistry.register_tag("a", XXpr)
class XprAttr(XXpr):
    """Expression attribute.

    tags[1]: name of attribute
    args[0]: index of expression in xd
    """

    def __init_(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XXpr.__init__(self, xd, ixval)

    @property
    def is_attr(self) -> bool:
        return True

    @property
    def attr(self) -> str:
        return self.tags[1]

    @property
    def expr(self) -> XXpr:
        return self.xd.xpr(int(self.args[0]))

    def __str__(self) -> str:
        return 'attr(' + self.attr + ',' + str(self.expr) + ')'
