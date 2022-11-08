# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Computes the sizes of types, variables, locations, and expressions."""

from typing import Dict, Mapping

from chb.ast.ASTCTyper import ASTCTyper
from chb.ast.ASTIndexer import ASTIndexer
import chb.ast.ASTNode as AST


intsizes: Dict[str, int] = {
    "ichar": 1,
    "ischar": 1,
    "iuchar": 1,
    "ibool": 1,
    "iint": 4,
    "iuint": 4,
    "ishort": 2,
    "iushort": 2,
    "ilong": 4,
    "iulong": 4,
    "ilonglong": 8,
    "iulonglong": 8
}


floatsizes: Dict[str, int] = {
    "float": 4,
    "fdouble": 8,
    "flongdouble": 8
}


class ASTByteSizeCalculationException(Exception):

    def __init__(self, nodetype: str, msg: str) -> None:
        Exception.__init__(
            self,
            "Unable to determine type of " + nodetype + "; " + msg)
        self._nodetype = nodetype
        self._msg = msg

    @property
    def nodetype(self) -> str:
        return self._nodetype


class ASTByteSizeCalculator(ASTIndexer):

    def __init__(
            self,
            ctyper: ASTCTyper,
            intsizes: Dict[str, int] = intsizes,
            floatsizes: Dict[str, int] = floatsizes,
            address_size: int = 4,
            structsizes: Dict[int, int] = {}) -> None:
        ASTIndexer.__init__(self)
        self._ctyper = ctyper
        self._intsizes = intsizes
        self._floatsizes = floatsizes
        self._address_size = address_size
        self._structsizes = structsizes

    @property
    def ctyper(self) -> "ASTCTyper":
        return self._ctyper

    @property
    def intsizes(self) -> Mapping[str, int]:
        return self._intsizes

    @property
    def floatsizes(self) -> Mapping[str, int]:
        return self._floatsizes

    @property
    def address_size(self) -> int:
        return self._address_size

    @property
    def structsizes(self) -> Mapping[int, int]:
        return self._structsizes

    def intsize(self, ikind: str) -> int:
        if ikind in self.intsizes:
            return self.intsizes[ikind]
        else:
            raise Exception("Integer kind " + ikind + " not found")

    def floatsize(self, fkind: str) -> int:
        if fkind in self.floatsizes:
            return self.floatsizes[fkind]
        else:
            raise Exception("Float kind " + fkind + " not found")

    def structsize(self, compkey: int) -> int:
        if compkey in self.structsizes:
            return self.structsizes[compkey]
        else:
            raise ASTByteSizeCalculationException("compinfo", str(compkey))

    def index_return_stmt(self, stmt: AST.ASTReturn) -> int:
        return 0

    def index_break_stmt(self, stmt: AST.ASTBreak) -> int:
        return 0

    def index_continue_stmt(self, stmt: AST.ASTContinue) -> int:
        return 0

    def index_loop_stmt(self, stmt: AST.ASTLoop) -> int:
        return 0

    def index_block_stmt(self, stmt: AST.ASTBlock) -> int:
        return 0

    def index_branch_stmt(self, stmt: AST.ASTBranch) -> int:
        return 0

    def index_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> int:
        return 0

    def index_goto_stmt(self, stmt: AST.ASTGoto) -> int:
        return 0

    def index_computedgoto_stmt(self, stmt: AST.ASTComputedGoto) -> int:
        return 0

    def index_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> int:
        return 0

    def index_label(self, label: AST.ASTLabel) -> int:
        return 0

    def index_case_label(self, label: AST.ASTCaseLabel) -> int:
        return 0

    def index_case_range_label(self, label: AST.ASTCaseRangeLabel) -> int:
        return 0

    def index_default_label(self, label: AST.ASTDefaultLabel) -> int:
        return 0

    def index_assign_instr(self, instr: AST.ASTAssign) -> int:
        return 0

    def index_call_instr(self, instr: AST.ASTCall) -> int:
        return 0

    def index_lval(self, lval: AST.ASTLval) -> int:
        ctype = lval.ctype(self.ctyper)
        if ctype is not None:
            return ctype.index(self)
        else:
            raise ASTByteSizeCalculationException("lval", str(lval))

    def index_varinfo(self, vinfo: AST.ASTVarInfo) -> int:
        if vinfo.vtype is not None:
            return vinfo.vtype.index(self)
        else:
            raise ASTByteSizeCalculationException("varinfo", vinfo.vname)

    def index_variable(self, var: AST.ASTVariable) -> int:
        return var.varinfo.index(self)

    def index_memref(self, memref: AST.ASTMemRef) -> int:
        ctype = memref.ctype(self.ctyper)
        if ctype is not None:
            return ctype.index(self)
        else:
            raise ASTByteSizeCalculationException("memref", str(memref))

    def index_no_offset(self, offset: AST.ASTNoOffset) -> int:
        return 0

    def index_field_offset(self, offset: AST.ASTFieldOffset) -> int:
        return 0

    def index_index_offset(self, offset: AST.ASTIndexOffset) -> int:
        return 0

    def index_integer_constant(self, expr: AST.ASTIntegerConstant) -> int:
        return self.intsize(expr.ikind)

    def index_floating_point_constant(
            self, expr: AST.ASTFloatingPointConstant) -> int:
        return self.floatsize(expr.fkind)

    def index_global_address(self, expr: AST.ASTIntegerConstant) -> int:
        return self.address_size

    def index_string_constant(self, expr: AST.ASTStringConstant) -> int:
        """Return the size of the string address, rather than the string itself."""

        return self.address_size

    def index_lval_expression(self, expr: AST.ASTLvalExpr) -> int:
        return expr.lval.index(self)

    def index_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> int:
        return self.intsize("iuint")

    def index_cast_expression(self, expr: AST.ASTCastExpr) -> int:
        return expr.cast_tgt_type.index(self)

    def index_unary_expression(self, expr: AST.ASTUnaryOp) -> int:
        ctype = expr.ctype(self.ctyper)
        if ctype is not None:
            return ctype.index(self)
        else:
            raise ASTByteSizeCalculationException("unaryop", str(expr))

    def index_binary_expression(self, expr: AST.ASTBinaryOp) -> int:
        ctype = expr.ctype(self.ctyper)
        if ctype is not None:
            return ctype.index(self)
        else:
            raise ASTByteSizeCalculationException("binaryop", str(expr))

    def index_question_expression(self, expr: AST.ASTQuestion) -> int:
        ctype = expr.ctype(self.ctyper)
        if ctype is not None:
            return ctype.index(self)
        else:
            raise ASTByteSizeCalculationException("question", str(expr))

    def index_address_of_expression(self, expr: AST.ASTAddressOf) -> int:
        return self.address_size

    def index_void_typ(self, typ: AST.ASTTypVoid) -> int:
        raise ASTByteSizeCalculationException("typvoid", "void has no size")

    def index_integer_typ(self, typ: AST.ASTTypInt) -> int:
        return self.intsize(typ.ikind)

    def index_float_typ(self, typ: AST.ASTTypFloat) -> int:
        if typ.fkind in self.floatsizes:
            return self.floatsize(typ.fkind)
        else:
            raise ASTByteSizeCalculationException("float", typ.fkind)

    def index_pointer_typ(self, typ: AST.ASTTypPtr) -> int:
        return self.address_size

    def index_array_typ(self, typ: AST.ASTTypArray) -> int:
        if typ.has_constant_size:
            return typ.size_value() * typ.tgttyp.index(self)
        else:
            raise ASTByteSizeCalculationException("array", "not constant size")

    def index_fun_typ(self, typ: AST.ASTTypFun) -> int:
        return self.address_size

    def index_funargs(self, funargs: AST.ASTFunArgs) -> int:
        return 0

    def index_funarg(self, funarg: AST.ASTFunArg) -> int:
        return funarg.argtyp.index(self)

    def index_named_typ(self, typ: AST.ASTTypNamed) -> int:
        return typ.typdef.index(self)

    def index_fieldinfo(self, finfo: AST.ASTFieldInfo) -> int:
        return finfo.fieldtype.index(self)

    def index_compinfo(self, cinfo: AST.ASTCompInfo) -> int:
        return self.structsize(cinfo.compkey)

    def index_comp_typ(self, typ: AST.ASTTypComp) -> int:
        return self.structsize(typ.compkey)

    def index_builtin_va_list(self, typ: AST.ASTTypBuiltinVAList) -> int:
        return self.address_size

    def index_enumitem(self, eitem: AST.ASTEnumItem) -> int:
        return eitem.itemexpr.index(self)

    def index_enuminfo(self, einfo: AST.ASTEnumInfo) -> int:
        return self.intsize(einfo.enumkind)

    def index_enum_typ(self, typ: AST.ASTTypEnum) -> int:
        return self.intsize(typ.enumkind)
