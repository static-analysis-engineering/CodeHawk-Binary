# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Construction of abstract syntax tree."""

import json

from typing import (
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    NewType,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING,
    Union)

import chb.ast.ASTNode as AST

from chb.ast.ASTSymbolTable import ASTSymbolTable, ASTLocalSymbolTable


ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])


nooffset = AST.ASTNoOffset()
voidtype = AST.ASTTypVoid()


class AbstractSyntaxTree:

    def __init__(
            self,
            faddr: str,
            fname: str,
            localsymboltable: ASTLocalSymbolTable) -> None:
        self._faddr = faddr
        self._fname = fname  # same as faddr if no name provided
        self._counter = 0
        self._tmpcounter = 0
        self._spans: List[ASTSpanRecord] = []
        self._symboltable = localsymboltable

        # integer types
        self._char_type = self.mk_integer_ikind_type("ichar")
        self._signed_char_type = self.mk_integer_ikind_type("ischar")
        self._unsigned_char_type = self.mk_integer_ikind_type("iuchar")
        self._bool_type = self.mk_integer_ikind_type("ibool")
        self._int_type = self.mk_integer_ikind_type("iint")
        self._unsigned_int_type = self.mk_integer_ikind_type("iuint")
        self._short_type = self.mk_integer_ikind_type("ishort")
        self._unsigned_short_type = self.mk_integer_ikind_type("iushort")
        self._long_type = self.mk_integer_ikind_type("ilong")
        self._unsigned_long_type = self.mk_integer_ikind_type("iulong")
        self._long_long_type = self.mk_integer_ikind_type("ilonglong")
        self._unsigned_long_long_type = self.mk_integer_ikind_type("iulonglong")

        # float types
        self._float_type = self.mk_float_fkind_type("float")
        self._double_type = self.mk_float_fkind_type("fdouble")
        self._long_double_type = self.mk_float_fkind_type("flongdouble")

    @property
    def fname(self) -> str:
        return self._fname

    @property
    def symboltable(self) -> ASTLocalSymbolTable:
        return self._symboltable

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self._spans

    def set_function_prototype(self, p: AST.ASTVarInfo) -> None:
        self.symboltable.set_function_prototype(p)

    def has_symbol(self, name: str) -> bool:
        return self.symboltable.has_symbol(name)

    def get_symbol(self, name: str) -> AST.ASTVarInfo:
        return self.symboltable.get_symbol(name)

    def add_symbol(
            self,
            name: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        return self.symboltable.add_symbol(
            name,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)

    def new_id(self) -> int:
        """A single sequence of id's is used for statement and instruction id.

        That is, the set of instruction id's is disjoint from the set of stmt id's.
        """
        id = self._counter
        self._counter += 1
        return id

    def add_span(self, span: ASTSpanRecord) -> None:
        self._spans.append(span)

    def add_instruction_span(self, id: int, base: str, bytestring: str) -> None:
        span: Dict[str, Union[str, int]] = {}
        span["base_va"] = base
        span["size"] = len(bytestring) // 2
        spanrec: Dict[str, Any] = {}
        spanrec["id"] = id
        spanrec["spans"] = [span]
        self.add_span(cast(ASTSpanRecord, spanrec))

    # ------------------------------------------------------ make statements ---

    def mk_block(self, stmts: List[AST.ASTStmt]) -> AST.ASTBlock:
        stmtid = self.new_id()
        return AST.ASTBlock(stmtid, stmts)

    def mk_return_stmt(self, expr: Optional[AST.ASTExpr]) -> AST.ASTReturn:
        id = self.new_id()
        return AST.ASTReturn(id, expr)

    def mk_branch(
            self,
            condition: Optional[AST.ASTExpr],
            ifbranch: AST.ASTStmt,
            elsebranch: AST.ASTStmt,
            relative_offset: int) -> AST.ASTStmt:
        stmtid = self.new_id()
        if condition is None:
            # create a new unknown (unitialized) variable
            condition = self.mk_tmp_lval_expression()
        return AST.ASTBranch(
            stmtid, condition, ifbranch, elsebranch, relative_offset)

    def mk_instr_sequence(
            self, instrs: List[AST.ASTInstruction]) -> AST.ASTInstrSequence:
        instrid = self.new_id()
        return AST.ASTInstrSequence(instrid, instrs)

    """Instructions
    There are two types of instructions: an assignment and a call. An
    assignment consists of a lhs (lval) and a rhs (expression). A call consists
    of an optional lhs (lval) to which the return value from the call is
    assigned, an expression that is the target of the call (an lval expression
    of a variable of type function in case of a direct call, or any other
    expression in case of an indirect call), and a list of expressions that
    represent the arguments to the call (preferably in conformance with the
    arity of the function type, but this is not checked).

    Instructions are assigned a unique instruction id. This instruction id can
    then be used to create a link with the instruction address (via the span)
    if desired.

    The set of instruction id's is disjoint from the set of statement id's (that
    is, if x is an instruction id, it is not also a statement id).

    Construction methods provided:
    ------------------------------
    - mk_assign: creates an assignment from a lhs (lval) and rhs (expression)
    - mk_call: creates a call from an optional lhs (lval), a target (expression),
        and a list of arguments (expressions)

    - mk_var_assign: creates an assignment from a variable name and rhs
        (expression); an lval with the given name is created (as described
        below under Variables)
    - mk_var_var_assign: creates an assignment from one variable name to another
        variable name; an lval and lval-expression for the two variables is
        created (as described below under Variables)

    - mk_var_call: creates a call instruction with a variable name as lhs argument
    - mk_tgt_call: creates a call instruction with a function name as tgt expression

    - mk_default_call: creates a call instruction with only a function name and
         arguments, and optionally a type for the function name; this method tries
         to determine if the function has a return value (i.e., does not return
         void). If so it will create a tmp variable with a description that
         indicates this variable holds a return value from the named function,
         if the function has void return type, the lval is set to None.

    Note: if function prototypes are available before creating call instructions
      it is preferable that they be entered in the symbol table up front.
    """

    def mk_assign(
            self,
            lval: AST.ASTLval,
            rhs: AST.ASTExpr) -> AST.ASTAssign:
        instrid = self.new_id()
        return AST.ASTAssign(instrid, lval, rhs)

    def mk_var_assign(
            self,
            vname: str,
            rhs: AST.ASTExpr) -> AST.ASTAssign:
        lval = self.mk_named_lval(vname)
        return self.mk_assign(lval, rhs)

    def mk_var_var_assign(
            self,
            vname: str,
            rhsname: str) -> AST.ASTAssign:
        rhs = self.mk_named_lval_expression(vname)
        return self.mk_var_assign(vname, rhs)

    def mk_call(
            self,
            lval: Optional[AST.ASTLval],
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr]) -> AST.ASTCall:
        instrid = self.new_id()
        return AST.ASTCall(instrid, lval, tgt, args)

    def mk_var_call(
            self,
            vname: str,
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr]) -> AST.ASTCall:
        lval = self.mk_named_lval(vname)
        return self.mk_call(lval, tgt, args)

    def mk_tgt_call(
            self,
            lval: Optional[AST.ASTLval],
            tgtname: str,
            args: List[AST.ASTExpr]) -> AST.ASTCall:
        tgtexpr = self.mk_named_lval_expression(tgtname)
        return self.mk_call(lval, tgtexpr, args)

    def mk_default_call(
            self,
            tgtvname: str,
            args: List[AST.ASTExpr],
            tgtvtype: Optional[AST.ASTTyp] = None) -> AST.ASTCall:
        tgtvinfo = self.mk_vinfo(tgtvname, vtype=tgtvtype)
        lval: Optional[AST.ASTLval] = None
        if (
                tgtvinfo.vtype is not None
                and tgtvinfo.vtype.is_function):
            tgttyp = cast(AST.ASTTypFun, tgtvinfo.vtype)
            if tgttyp.is_void:
                lval = None
            else:
                lval = self.mk_tmp_lval(vdescr="return value from " + tgtvname)
        tgtexpr = self.mk_vinfo_lval_expression(tgtvinfo)
        return self.mk_call(lval, tgtexpr, args)

    """Variables

    Variables have a name. For named variables it is the user's responsibility
    to ensure that distinct variables (i.e. distinct storage locations) have
    distinct names (within a function) and that distinct global variables have
    distinct names (across all functions). Local variables in different\
    functions may have the same name (functions have different name spaces).

    The basic data structure for a variable is the ASTVarInfo, which holds the
    name, type (optional), the parameter index (zero-based) if the variable is
    a formal parameter to a function, the global address (optional) if the
    address is known, and an optional description of what the variable holds.
    The varinfo is stored in the local or global symbol table on first creation.

    The first creation of the varinfo determines the associate data. Once a
    variable exists (either in the global symbol or local symbol table)
    subsequent calls to create a variable with the same name (in the same name
    space result in retrieval of the existing varinfo rather than creating a
    new one, thereby ignoring the associate data provided.

    Only one instance exists of the ASTVarInfo data structure, held in the
    symboltable for each name. Multiple instances of related ASTVariable,
    ASTLval, and ASTLvalExpr may exist within the abstract syntax tree structure
    (these will all be collapsed into one by the serializer).

    Temporary variables are automatically given unique names.

    Construction methods provided:
    ------------------------------
    - mk_vinfo : creates/returns a varinfo data structure from the symboltable
    - mk_vinfo_variable: creates/returns a variable from a vinfo
    - mk_vinfo_lval: creates/return an lval (lhs) (with optional offset) from
         a vinfo
    - mk_vinfo_lval_expression: creates/returns an lval-expression (rhs) (with
         optional offset) from a vinfo

    - mk_named_variable: creates a variable with the given a name (and will
         implicitly create a varinfo, if necessary)
    - mk_named_lval: creates an lval (lhs) (with optional offset) with the given
         name
    - mk_named_lval_expression: creates an lval expression (rhs) (with optional
         offset) with the given name

    - mk_tmp_variable: creates a new varinfo/variable with a unique name
    - mk_tmp_lval: creates a new varinfo/lval (lhs) with a unique name
    - mk_tmp_lval_expression: creates new varinfo/lval-expression (rhs) with a
         unique name
    """

    def mk_vinfo(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        if globaladdress is not None:
            vinfo = self.symboltable.add_global_symbol(
                vname,
                vtype=vtype,
                globaladdress=globaladdress,
                vdescr=vdescr)
        else:
            vinfo = self.symboltable.add_symbol(
                vname,
                vtype=vtype,
                parameter=parameter,
                vdescr=vdescr)
        return vinfo

    def mk_vinfo_variable(self, vinfo: AST.ASTVarInfo) -> AST.ASTVariable:
        return AST.ASTVariable(vinfo)

    def mk_vinfo_lval(
            self,
            vinfo: AST.ASTVarInfo,
            offset: AST.ASTOffset = nooffset) -> AST.ASTLval:
        var = self.mk_vinfo_variable(vinfo)
        return AST.ASTLval(var, offset)

    def mk_vinfo_lval_expression(
            self,
            vinfo: AST.ASTVarInfo,
            offset: AST.ASTOffset = nooffset) -> AST.ASTLvalExpr:
        lval = self.mk_vinfo_lval(vinfo, offset)
        return AST.ASTLvalExpr(lval)

    def mk_named_variable(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVariable:
        vinfo = self.mk_vinfo(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)
        return self.mk_vinfo_variable(vinfo)

    def mk_named_lval(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None,
            offset: AST.ASTOffset = nooffset) -> AST.ASTLval:
        var = self.mk_named_variable(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)
        return AST.ASTLval(var, offset)

    def mk_named_lval_expression(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None,
            offset: AST.ASTOffset = nooffset) -> AST.ASTLvalExpr:
        lval = self.mk_named_lval(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr,
            offset=offset)
        return AST.ASTLvalExpr(lval)

    def new_tmp_name(self) -> str:
        tmpid = self._tmpcounter
        self._tmpcounter += 1
        return "__asttmp_" + str(tmpid) + "__"

    def mk_tmp_variable(
            self,
            vtype: Optional[AST.ASTTyp] = None,
            vdescr: Optional[str] = None) -> AST.ASTVariable:
        vname = self.new_tmp_name()
        return self.mk_named_variable(vname, vtype=vtype, vdescr=vdescr)

    def mk_tmp_lval(
            self,
            vtype: Optional[AST.ASTTyp] = None,
            vdescr: Optional[str] = None) -> AST.ASTLval:
        vname = self.new_tmp_name()
        return self.mk_named_lval(vname, vtype=vtype, vdescr=vdescr)

    def mk_tmp_lval_expression(
            self,
            vtype: Optional[AST.ASTTyp] = None,
            vdescr: Optional[str] = None) -> AST.ASTLvalExpr:
        vname = self.new_tmp_name()
        return self.mk_named_lval_expression(
            vname, vtype=vtype, vdescr=vdescr)

    """Offsets

    The default offset in lval creation is NoOffset, provided as constant
    value nooffset.

    The other two options are a field offset (to access struct fields) and
    an index offset (to access array elements).

    To create a field offset, create a the compinfo data structure first to
    obtain the compkey value of the struct. The type of the field can then
    be obtained from the compinfo data structure.

    An index offset can be created either with an integer or with an expression;
    note that by C semantics the index offset must be scaled by the size of
    the array element.

    The field offset and index offset can have sub-offsets. Default for these
    sub-offsets is nooffset.

    Construction methods provided:
    - mk_field_offset: create a field offset from the name of the field and
         the key of corresponding struct (compinfo)

    - mk_scalar_index_offset: create an index offset from an integer value
    - mk_expr_index_offset: create an index offset from an expression
    """

    def mk_field_offset(
            self,
            fieldname: str,
            compkey: int,
            offset: AST.ASTOffset = nooffset) -> AST.ASTFieldOffset:
        return AST.ASTFieldOffset(fieldname, compkey, offset)

    def mk_scalar_index_offset(
            self,
            index: int,
            offset: AST.ASTOffset = nooffset) -> AST.ASTIndexOffset:
        indexexpr = self.mk_integer_constant(index)
        return AST.ASTIndexOffset(indexexpr, offset)

    def mk_expr_index_offset(
            self,
            indexexpr: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset) -> AST.ASTIndexOffset:
        return AST.ASTIndexOffset(indexexpr, offset)

    """Other lvals and expressions

    Lvals (lhs) can also be made from dereferenced pointer expressions
    (memory reference, or memref expressions).

    Several kinds of other expressions can be created.

    Construction methods provided:
    - mk_lval: create an lval from a generic lhost and offset
    - mk_lval_expression: create an lval expression for a generic lhost and offset

    - mk_memref: create an lhs base value (lhost) from an expression
    - mk_memref_lval: create an lval (lhs) from a memref and an offset
    - mk_memref_expression: create an val expression (rhs) from a a memref
        and an offset

    - mk_integer_constant: create an integer constant from an integer
    - mk_string_constant: create a string constant from a string and the
        expression that produced the string address, and the string address
        itself (in hex) (to ensure proper identification)

    - mk_unary_expression: create an expression that applies a unary operator
        to an expression
    - mk_binary_expression: create an expression that applies a binary operator
        to two expressions
    - mk_question_expression: create an expression that applies the question
        operator to three expressions
    - mk_address_of_expression: create an expression that applies the address-of
        operator an lval
    - mk_cast_expression: create an expression that casts another expression to
        a given type

    Some special-purpose expression
    - mk_plus_expression: create a sum binary expression
    - mk_minus_expression: create a difference binary expression
    - mk_multiplication_expression: create a product binary expression

    - mk_negation_expression: create a negation unary expression
    - mk_bitwise_not_expression: create a bitwise not unary expression
    - mk_logical_not_expression: create a logical not unary expression

    """

    def mk_lval(self, lhost: AST.ASTLHost, offset: AST.ASTOffset) -> AST.ASTLval:
        return AST.ASTLval(lhost, offset)

    def mk_lval_expression(self, lval: AST.ASTLval) -> AST.ASTLvalExpr:
        return AST.ASTLvalExpr(lval)

    def mk_memref(self, memexp: AST.ASTExpr) -> AST.ASTMemRef:
        return AST.ASTMemRef(memexp)

    def mk_memref_lval(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset) -> AST.ASTLval:
        memref = self.mk_memref(memexp)
        return AST.ASTLval(memref, offset)

    def mk_memref_expression(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset) -> AST.ASTExpr:
        memreflval = self.mk_memref_lval(memexp, offset)
        return AST.ASTLvalExpr(memreflval)

    def mk_integer_constant(self, cvalue: int) -> AST.ASTIntegerConstant:
        return AST.ASTIntegerConstant(cvalue)

    def mk_string_constant(
            self,
            expr: AST.ASTExpr,
            cstr: str,
            string_address: str) -> AST.ASTStringConstant:
        return AST.ASTStringConstant(expr, cstr, string_address)

    def mk_address_of_expression(self, lval: AST.ASTLval) -> AST.ASTAddressOf:
        return AST.ASTAddressOf(lval)

    def mk_binary_expression(
            self,
            op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr) -> AST.ASTExpr:
        return AST.ASTBinaryOp(op, exp1, exp2)

    def mk_plus_expression(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression("plus", exp1, exp2)

    def mk_minus_expression(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression("minus", exp1, exp2)

    def mk_multiplication_expression(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression("mult", exp1, exp2)

    def mk_question_expression(
            self,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            exp3: AST.ASTExpr) -> AST.ASTExpr:
        return AST.ASTQuestion(exp1, exp2, exp3)

    def mk_unary_expression(self, op: str, exp: AST.ASTExpr) -> AST.ASTExpr:
        return AST.ASTUnaryOp(op, exp)

    def mk_negation_expression(self, exp: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_unary_expression("neg", exp)

    def mk_bitwise_not_expression(self, exp: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_unary_expression("bnot", exp)

    def mk_logical_not_expression(self, exp: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_unary_expression("lnot", exp)

    def mk_cast_expression(
            self, tgttyp: AST.ASTTyp, exp: AST.ASTExpr) -> AST.ASTExpr:
        return AST.ASTCastExpr(tgttyp, exp)

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self._spans:
            lines.append(str(r))
        return "\n".join(lines)

    """Types

    """

    def mk_integer_ikind_type(self, ikind: str) -> AST.ASTTypInt:
        return AST.ASTTypInt(ikind)

    @property
    def char_type(self) -> AST.ASTTypInt:
        return self._char_type

    @property
    def signed_char_type(self) -> AST.ASTTypInt:
        return self._signed_char_type

    @property
    def unsigned_char_type(self) -> AST.ASTTypInt:
        return self._unsigned_char_type

    @property
    def bool_type(self) -> AST.ASTTypInt:
        return self._bool_type

    @property
    def int_type(self) -> AST.ASTTypInt:
        return self._int_type

    @property
    def unsigned_int_type(self) -> AST.ASTTypInt:
        return self._unsigned_int_type

    @property
    def short_type(self) -> AST.ASTTypInt:
        return self._short_type

    @property
    def unsigned_short_type(self) -> AST.ASTTypInt:
        return self._unsigned_short_type

    @property
    def long_type(self) -> AST.ASTTypInt:
        return self._long_type

    @property
    def unsigned_long_type(self) -> AST.ASTTypInt:
        return self._unsigned_long_type

    @property
    def long_long_type(self) -> AST.ASTTypInt:
        return self._long_long_type

    @property
    def unsigned_long_long_type(self) -> AST.ASTTypInt:
        return self._unsigned_long_type

    def mk_float_fkind_type(self, fkind: str) -> AST.ASTTypFloat:
        return AST.ASTTypFloat(fkind)

    @property
    def float_type(self) -> AST.ASTTypFloat:
        return self._float_type

    @property
    def double_type(self) -> AST.ASTTypFloat:
        return self._double_type

    @property
    def long_double_type(self) -> AST.ASTTypFloat:
        return self._long_double_type

    def mk_pointer_type(self, tgttype: AST.ASTTyp) -> AST.ASTTypPtr:
        return AST.ASTTypPtr(tgttype)

    def mk_array_type(
            self,
            tgttype: AST.ASTTyp,
            size: Optional[AST.ASTExpr]) -> AST.ASTTyp:
        return AST.ASTTypArray(tgttype, size)

    def mk_function_type_argument(
            self, argname: str, argtype: AST.ASTTyp) -> AST.ASTFunArg:
        return AST.ASTFunArg(argname, argtype)

    def mk_function_type_arguments(
            self, args: List[AST.ASTFunArg]) -> AST.ASTFunArgs:
        return AST.ASTFunArgs(args)

    def mk_function_type(
            self,
            returntype: AST.ASTTyp,
            arguments: Optional[AST.ASTFunArgs],
            varargs: bool = False) -> AST.ASTTypFun:
        return AST.ASTTypFun(returntype, arguments, varargs=varargs)

    def mk_function_with_arguments_type(
            self,
            returntype: AST.ASTTyp,
            arguments: List[Tuple[str, AST.ASTTyp]],
            varargs: bool = False) -> AST.ASTTypFun:
        funargs = AST.ASTFunArgs(
            [AST.ASTFunArg(name, typ) for (name, typ) in arguments])
        return AST.ASTTypFun(returntype, funargs, varargs=varargs)

    def mk_typedef(self, name: str, typ: AST.ASTTyp) -> AST.ASTTypNamed:
        return AST.ASTTypNamed(name, typ)
