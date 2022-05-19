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
"""Rewrites the AST using structured datatype definitions."""

from typing import cast, Dict, List, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable
from chb.ast.ASTTransformer import ASTTransformer


class ASTRewriter(ASTTransformer):

    def __init__(self, symboltable: ASTLocalSymbolTable) -> None:
        self._symboltable = symboltable
        self._currentid: int = 0  # id of the current stmt/instr
        self._notes: Dict[int, List[str]] = {}

    @property
    def local_symboltable(self) -> ASTLocalSymbolTable:
        return self._symboltable

    @property
    def global_symboltable(self) -> ASTGlobalSymbolTable:
        return self.local_symboltable.globaltable

    @property
    def notes(self) -> Dict[int, List[str]]:
        return self._notes

    @property
    def currentid(self) -> int:
        return self._currentid

    def set_currentid(self, id: int) -> None:
        self._currentid = id

    def add_note(self, id: int, note: str) -> None:
        self._notes.setdefault(id, [])
        self._notes[id].append(note)

    def rewrite_code(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        return self.rewrite_stmt(stmt)

    def rewrite_stmt(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        if stmt.is_ast_return:
            return self.transform_return_stmt(cast(AST.ASTReturn, stmt))

        elif stmt.is_ast_block:
            return self.transform_block_stmt(cast(AST.ASTBlock, stmt))

        elif stmt.is_ast_instruction_sequence:
            return self.transform_instruction_sequence_stmt(
                cast(AST.ASTInstrSequence, stmt))

        elif stmt.is_ast_branch:
            return self.transform_branch_stmt(cast(AST.ASTBranch, stmt))

        else:
            raise Exception("Statement type not recognized: " + stmt.tag)

    def transform_return_stmt(self, stmt: AST.ASTReturn) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)
        if stmt.has_return_value():
            return AST.ASTReturn(stmt.stmtid, stmt.expr.transform(self))
        else:
            return stmt

    def transform_block_stmt(self, stmt: AST.ASTBlock) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)
        return AST.ASTBlock(
            stmt.stmtid, [s.transform(self) for s in stmt.stmts])

    def transform_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)
        return AST.ASTInstrSequence(
            stmt.stmtid, [i.transform(self) for i in stmt.instructions])

    def transform_branch_stmt(self, stmt: AST.ASTBranch) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)
        return AST.ASTBranch(
            stmt.stmtid,
            stmt.condition.transform(self),
            stmt.ifstmt.transform(self),
            stmt.elsestmt.transform(self),
            stmt.relative_offset)

    def transform_assign_instr(self, instr: AST.ASTAssign) -> AST.ASTInstruction:
        self.set_currentid(instr.instrid)
        return AST.ASTAssign(
            instr.instrid, instr.lhs.transform(self), instr.rhs.transform(self))

    def transform_call_instr(self, instr: AST.ASTCall) -> AST.ASTInstruction:
        self.set_currentid(instr.instrid)
        lhsxform = None if instr.lhs is None else instr.lhs.transform(self)
        return AST.ASTCall(
            instr.instrid,
            lhsxform,
            instr.tgt.transform(self),
            [a.transform(self) for a in instr.arguments])

    def transform_lval(self, lval: AST.ASTLval) -> AST.ASTLval:

        def default() -> AST.ASTLval:
            return AST.ASTLval(
                lval.lhost.transform(self), lval.offset.transform(self))

        lhost = lval.lhost.transform(self)
        offset = lval.offset.transform(self)

        if lhost.is_memref:
            lhost = cast(AST.ASTMemRef, lhost)
            if lhost.memexp.is_ast_binary_op:
                memexp = cast(AST.ASTBinaryOp, lhost.memexp)
                return self.rewrite_compound_memref_to_lval(memexp, offset)

            else:
                self.add_note(
                    self.currentid,
                    "rewrite-lval-1; memexp: " + str(lhost.memexp))
                return default()
        else:
            return default()

    def transform_varinfo(self, vinfo: AST.ASTVarInfo) -> AST.ASTVarInfo:
        return vinfo

    def transform_variable(self, var: AST.ASTVariable) -> AST.ASTLHost:
        return var

    def transform_memref(self, memref: AST.ASTMemRef) -> AST.ASTMemRef:
        return AST.ASTMemRef(memref.memexp.transform(self))

    def transform_no_offset(self, offset: AST.ASTNoOffset) -> AST.ASTOffset:
        return offset

    def transform_field_offset(
            self, offset: AST.ASTFieldOffset) -> AST.ASTOffset:
        return AST.ASTFieldOffset(
            offset.fieldname, offset.compkey, offset.offset.transform(self))

    def transform_index_offset(
            self, offset: AST.ASTIndexOffset) -> AST.ASTOffset:
        return AST.ASTIndexOffset(
            offset.index_expr.transform(self), offset.offset.transform(self))

    def transform_integer_constant(
            self, expr: AST.ASTIntegerConstant) -> AST.ASTExpr:
        if expr.cvalue == 0:
            return expr

        # transform into global address if found in symboltable
        hexvalue = hex(expr.cvalue)
        basevarinfo = self.global_symboltable.global_variable_name(hexvalue)
        if basevarinfo is not None:
            basevar = AST.ASTVariable(basevarinfo)
            if basevarinfo.vtype is not None and basevarinfo.vtype.is_array:
                offset = AST.ASTIntegerConstant(0)
                indexoffset = AST.ASTIndexOffset(offset, AST.ASTNoOffset())
                baselval = AST.ASTLval(basevar, indexoffset)
            else:
                baselval = AST.ASTLval(basevar, AST.ASTNoOffset())
            lvalexpr = AST.ASTAddressOf(baselval)
            return AST.ASTGlobalAddressConstant(expr.cvalue, lvalexpr)
        else:
            return expr

    def transform_global_address(
            self, expr: AST.ASTGlobalAddressConstant) -> AST.ASTExpr:
        return expr

    def transform_string_constant(
            self, expr: AST.ASTStringConstant) -> AST.ASTExpr:
        return expr

    def transform_lval_expression(self, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        return AST.ASTLvalExpr(expr.lval.transform(self))

    def transform_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> AST.ASTExpr:
        return expr

    def transform_cast_expression(self, expr: AST.ASTCastExpr) -> AST.ASTExpr:
        return AST.ASTCastExpr(expr.cast_tgt_type, expr.cast_expr.transform(self))

    def transform_unary_expression(self, expr: AST.ASTUnaryOp) -> AST.ASTExpr:
        return AST.ASTUnaryOp(expr.op, expr.exp1.transform(self))

    def transform_binary_expression(self, expr: AST.ASTBinaryOp) -> AST.ASTExpr:
        return AST.ASTBinaryOp(
            expr.op, expr.exp1.transform(self), expr.exp2.transform(self))

    def transform_question_expression(
            self, expr: AST.ASTQuestion) -> AST.ASTExpr:
        return AST.ASTQuestion(
            expr.exp1.transform(self),
            expr.exp2.transform(self),
            expr.exp3.transform(self))

    def transform_address_of_expression(
            self, expr: AST.ASTAddressOf) -> AST.ASTExpr:
        return AST.ASTAddressOf(expr.lval.transform(self))

    def rewrite_compound_memref_to_lval(
            self,
            memexp: AST.ASTBinaryOp,
            offset: AST.ASTOffset) -> AST.ASTLval:

        def default() -> AST.ASTLval:
            return AST.ASTLval(AST.ASTMemRef(memexp), offset)

        return default()

    '''
        instrid = self.currentid
        base = memexp.exp1
        offsetexp = memexp.exp2
        if memexp.op == "plus":
            if (
                    (base.is_ast_addressof or base.is_global_address)
                    and base.ctype is not None
                    and base.ctype.is_array):
                basetype = cast("BCTypArray", base.ctype)
                eltsize = basetype.tgttyp.byte_size()
                indexexp = self.scale_expr(offsetexp, eltsize)
                newoffset = AST.ASTIndexOffset(indexexp, offset)
                baselhost = cast(AST.ASTLvalExpr, base).lval.lhost
                self.add_note(
                    instrid,
                    "rewrite-compound-memref-to-lval: array: "
                    + str(base)
                    + " with type "
                    + str(base.ctype)
                    + " and element size "
                    + str(eltsize)
                    + " and index expression "
                    + str(indexexp)
                    + " and baselhost "
                    + str(baselhost))
                return AST.ASTLval(baselhost, newoffset)

            else:
                self.add_note(
                    instrid,
                    "rewrite-compound-memref-to-lval: "
                    + str(base)
                    + " with type "
                    + str(base.ctype))
                return default()

            if base.is_global_address:
                basexpr = base.address_expr
                tgttyp = basexpr.address_tgt_type
                if tgttyp is not None:
                    if tgttyp.is_array:
                        tgttyp = cast("BCTypArray", tgttyp)
                        eltsize = tgttyp.tgttyp.byte_size()
                        self.add_note(
                            instrid,
                            "rewrite-compound-memref-to-lval: global array: "
                            + str(tgttyp)
                            + " with element size "
                            + str(eltsize))
                    self.add_note(
                        instrid,
                        "rewrite-compound-memref-to-lval: global-address: "
                        + str(base) + " " + str(tgttyp))

            self.add_note(
                instrid,
                "rewrite-compound-memref-to-lval: "
                + str(base)
                + ", "
                + str(offsetexp))
            return default()
        else:
            return default()


    def rewrite_lhost(self, instrid: int, lhost: AST.ASTLHost) -> AST.ASTLHost:
        if lhost.is_variable:
            return lhost
        elif lhost.is_memref:
            return self.rewrite_memref(instrid, cast(AST.ASTMemRef, lhost))
        else:
            raise UF.CHBError("Unexpected lhost type: " + lhost.tag)

    def rewrite_memref(
            self, instrid: int, memref: AST.ASTMemRef) -> AST.ASTLHost:
        return AST.ASTMemRef(self.rewrite_expr(instrid, memref.memexp))

    def rewrite_offset(
            self, instrid: int, offset: AST.ASTOffset) -> AST.ASTOffset:
        return offset

    def rewrite_expr(self, instrid: int, expr: AST.ASTExpr) -> AST.ASTExpr:
        if expr.is_ast_constant:
            return self.rewrite_constant(instrid, cast(AST.ASTConstant, expr))

        elif expr.is_ast_binary_op:
            return self.rewrite_binary_op(instrid, cast(AST.ASTBinaryOp, expr))

        elif expr.is_ast_substituted_expr:
            expr = cast(AST.ASTSubstitutedExpr, expr)
            return self.rewrite_substituted_expr(instrid, expr)

        elif expr.is_ast_lval_expr:
            return self.rewrite_lval_expr(instrid, cast(AST.ASTLvalExpr, expr))

        else:
            return expr

    def rewrite_constant(self, instrid: int, c: AST.ASTConstant) -> AST.ASTExpr:
        if c.is_string_constant:
            return c
        elif c.is_integer_constant and c.cvalue == 0:
            return c
        elif c.is_global_address:
            return c
        elif c.is_integer_constant:
            c = cast(AST.ASTIntegerConstant, c)
            basevarinfo = self.global_symboltable.global_variable_name(hex(c.cvalue))
            if basevarinfo is not None:
                basevar = AST.ASTVariable(basevarinfo)
                baselval = AST.ASTLval(basevar, AST.ASTNoOffset())
                addrexpr = AST.ASTAddressOf(baselval)
                result = AST.ASTGlobalAddressConstant(c.cvalue, addrexpr)
                self.add_note(
                    instrid,
                    "rewrite-constant: "
                    + hex(c.cvalue)
                    + " -> "
                    + str(result)
                    + " ("
                    + str(result.address_tgt_type)
                    + ")")
                return result
            else:
                self.add_note(
                    instrid,
                    "rewrite-constant: " + str(c) + " (" + hex(c.cvalue) + ")")
                return c
        else:
            return c

    def rewrite_substituted_expr(
            self, instrid: int, expr: AST.ASTSubstitutedExpr) -> AST.ASTExpr:
        return AST.ASTSubstitutedExpr(
            expr.lval,
            expr.assign_id,
            self.rewrite_expr(instrid, expr.substituted_expr))

    def rewrite_lval_expr(
            self, instrid: int, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        return AST.ASTLvalExpr(self.rewrite_lval(instrid, expr.lval))

    def rewrite_binary_op(
            self, instrid: int, binop: AST.ASTBinaryOp) -> AST.ASTExpr:
        return AST.ASTBinaryOp(
            binop.op,
            self.rewrite_expr(instrid, binop.exp1),
            self.rewrite_expr(instrid, binop.exp2))
    '''

    def scale_expr(self, expr: AST.ASTExpr, scale: int) -> AST.ASTExpr:
        instrid = self.currentid
        if expr.is_ast_binary_op:
            expr = cast(AST.ASTBinaryOp, expr)
            if expr.op == "lsl" and expr.exp2.is_integer_constant:
                shiftamount = cast(AST.ASTIntegerConstant, expr.exp2).cvalue
                if (2 ** shiftamount) == scale:
                    self.add_note(
                        instrid, "scale " + str(expr) + " to " + str(expr.exp1))
                    return expr.exp1
                self.add_note(
                    instrid,
                    "scale-expression: with operator "
                    + expr.op
                    + " and operands "
                    + str(expr.exp1)
                    + " and "
                    + str(expr.exp2))
            return expr
        else:
            return expr

    def __str__(self) -> str:
        lines: List[str] = []
        for (id, notes) in sorted(self.notes.items()):
            print(str(id))
            for n in notes:
                print("  " + n)
        return "\n".join(lines)

    def transform_void_typ(self, t: AST.ASTTypVoid) -> AST.ASTTyp:
        return t

    def transform_integer_typ(self, t: AST.ASTTypInt) -> AST.ASTTyp:
        return t

    def transform_float_typ(self, t: AST.ASTTypFloat) -> AST.ASTTyp:
        return t

    def transform_pointer_typ(self, t: AST.ASTTypPtr) -> AST.ASTTyp:
        return t

    def transform_array_typ(self, t: AST.ASTTypArray) -> AST.ASTTyp:
        return t

    def transform_fun_typ(self, t: AST.ASTTypFun) -> AST.ASTTyp:
        return t

    def transform_funargs(self, a: AST.ASTFunArgs) -> AST.ASTFunArgs:
        return a

    def transform_funarg(self, a: AST.ASTFunArg) -> AST.ASTFunArg:
        return a

    def transform_named_typ(self, t: AST.ASTTypNamed) -> AST.ASTTyp:
        return t

    def transform_builtin_va_list(
            self, t: AST.ASTTypBuiltinVAList) -> AST.ASTTypBuiltinVAList:
        return t

    def transform_comp_typ(self, t: AST.ASTTypComp) -> AST.ASTTyp:
        return t

    def transform_compinfo(self, cinfo: AST.ASTCompInfo) -> AST.ASTCompInfo:
        return cinfo

    def transform_fieldinfo(self, finfo: AST.ASTFieldInfo) -> AST.ASTFieldInfo:
        return finfo
