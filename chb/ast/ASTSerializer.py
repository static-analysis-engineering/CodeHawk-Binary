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
"""AST serialization to json format.

Serialization formats:
======================

Statements
----------

- return_stmt:
  tag: "return"
  args:
     0: stmtid
     1: return expr, or -1 if returning void

- block-stmt:
  tag: "block"
  args:
    0: stmtid
    1..: id's of statements contained in the block

- branch-stmt:
  tag: "if"
  pc-offset: integer that gives the distance between this statement and the
             target statement
  args:
    0: stmtid
    1: id of condition expr
    2: id of then-branch statement
    3: id of else-branch statement

- instruction-sequence:
  tag: "instrs"
  args:
    0: stmtid
    1..: id's of instructions contained in the statement


Instructions
------------

- call-instr:
  tag: "call"
  args:
    0: instrid
    1: id of left-hand-side (lval) or -1 if there is no left-hand-side
    2: id of expression that represents the target of the call
    3..: id's of the argument expressions

- assign-instr
  tag: "assign"
  args:
    0: instrid
    1: id of left-hand-side (lval)
    2: id of right-hand-side (expr)


Lval-related nodes
------------------

- varinfo:
  tag: "varinfo"
  name: name of the variable
  (optional)descr: description of the variable, free-form string
  args:
    0: id of the type of the variable of -1 if not known
    1: index of parameter (zero-based) if this is a formal or -1 otherwise
    2: global address (integer) if this variable is a global and its address
       is known, -1 otherwise

- variable
  tag: "var"
  name: name of the variable
  args:
    0: id of the varinfo of this variable

- memory-reference
  tag: "memref"
  args:
    0: id of the expression that gets dereferenced

- no-offset
  tag: "no-offset"
  args: -

- field-offset
  tag: "field-offset"
  fname: name of the field (string)
  args:
    0: compinfo compkey
    1: id of sub-offset

- index-offset
  tag: "index-offset"
  args:
    0: id of index expression
    1: id of sub-offset


Expressions
-----------

- integer-constant
  tag: "integer-constant"
  value: integer value as a string
  args: -

- global-address
  tag: "global-address"
  value: integer value as a string
  args:
     0: id of the expression that forms the address (lval-expr)

- string-constant
  tag: "string-constant"
  cstr: the string
  (optional)va: the address of the string (as a hex-string)
  args:
    0: id of expression that forms the string address, or -1 if not known

- lval-expression
  tag: "lval-expr"
  args:
    0: id of lval

- substituted-expression
  tag: "substituted-expression"
  assigned: instrid of the assign instruction that provides the expression
  args:
    0: id of the lval of the original lval-expression
    1: id of the substituted expression

- size-of-type-expression
  tag: "size-of"
  args:
    0: id of the type of which the size is taken

- cast-expression
  tag: "cast-expr"
  args:
    0: id of the target type to which is cast
    1: id of the expression being cast

- unary-expression
  tag: "unary-op"
  op: name of operator ("neg", or "bnot", or "lnot")
  args:
    0: id of subexpression

- binary-expression
  tag: "binary-op"
  op: name of operator ("plus", "minus", "mult", "div", "mod", "lsl", "lsr",
        "asr", "lt", "gt", "le", "ge", "eq", "ne", "band", "bxor", "bor",
        "land", "lor")
  args:
    0: id of first subexpression
    1: id of second subexpression

- question-expression
  tag: "question"
  args:
    0: id of first subexpression (conditional)
    1: id of second subexpression
    2: id of third subexpression


Types
-----

- void-type:
  tag: "void"
  args: -

- integer-type
  tag: "int"
  ikind: indication of the signedness/width of the integer
         ("ichar", "ischar", "iuchar", "ibool", "iint", "iuint", "ishort",
          "iushort", "ilong", "iulong", "ilonglong")
  args: -

- float-type
  tag: "float"
  fkind: indication of the precision ("float", "fdouble", "flongdouble")
  args: -

- pointer type
  tag: "ptr"
  args:
    0: id of the target type of the pointer

- array type
  tag: "array"
  args:
    0: id of the element type
    1: id of the expression that denotes the size or -1 if not available

- function type
  tag: "funtype"
  args:
    0: id of the return type
    1: id of the function arguments (funargs), or -1 if not available
    2: 1 if this function is a varargs function, 0 otherwise

- function-arguments
  tag: "funargs"
  args:
    0..: id's of the individual function-arguments (funarg)

- function-argument
  tag: "funarg"
  name: name of the function argument (in the signature)
  args:
    0: id of the type of the function argument

- named type (typedef)
  tag: "typdef"
  name: name given to the type
  args:
    0: id of the type assigned to the name

- struct/union type
  tag: "comptyp"
  cname: name of the struct/union
  args:
    0: compkey

- builtin-va-list
  tag: "builtin-va-list"
  args: -

- fieldinfo (struct/union field)
  tag: "fieldinfo"
  name: name of the field
  args:
    0: id of the type of the field
    1: compkey of the struct to which this field belongs
    2: byteoffset of the field in the struct if available, -1 otherwise

- compinfo (struct/union)
  tag: "compinfo"
  name: name of the struct/union
  args:
    0: 1 if this compinfo represents a union, 0 otherwise
    1..: id's of fieldinfo's that make up the struct or union

"""

from typing import Any, cast, Dict, List, Tuple

from chb.ast.ASTIndexer import ASTIndexer
import chb.ast.ASTNode as AST
from chb.ast.ASTNodeDictionary import ASTNodeDictionary, get_key


class ASTSerializer(ASTIndexer):

    def __init__(self) -> None:
        ASTIndexer.__init__(self)
        self._table = ASTNodeDictionary()

    @property
    def table(self) -> ASTNodeDictionary:
        return self._table

    def records(self) -> List[Dict[str, Any]]:
        return self.table.records()

    def add(self, tags: List[str], args: List[int], node: Dict[str, Any]) -> int:
        node["args"] = args
        return self.table.add(get_key(tags, args), node)

    def index_stmt(self, stmt: AST.ASTStmt) -> int:
        if stmt.is_ast_return:
            return self.index_return_stmt(cast(AST.ASTReturn, stmt))

        elif stmt.is_ast_block:
            return self.index_block_stmt(cast(AST.ASTBlock, stmt))

        elif stmt.is_ast_instruction_sequence:
            return self.index_instruction_sequence_stmt(
                cast(AST.ASTInstrSequence, stmt))

        elif stmt.is_ast_branch:
            return self.index_branch_stmt(cast(AST.ASTBranch, stmt))

        else:
            raise Exception("Statement type not recognized: " + stmt.tag)

    def index_return_stmt(self, stmt: AST.ASTReturn) -> int:
        tags: List[str] = [stmt.tag]
        args: List[int] = [stmt.stmtid]
        node: Dict[str, Any] = {"tag": stmt.tag}
        if stmt.has_return_value():
            args.append(stmt.expr.index(self))
        else:
            args.append(-1)
        return self.add(tags, args, node)

    def index_block_stmt(self, stmt: AST.ASTBlock) -> int:
        tags: List[str] = [stmt.tag]
        args: List[int] = [stmt.stmtid]
        node: Dict[str, Any] = {"tag": stmt.tag}
        args.extend([s.index(self) for s in stmt.stmts])
        return self.add(tags, args, node)

    def index_branch_stmt(self, stmt: AST.ASTBranch) -> int:
        tags: List[str] = [stmt.tag, str(stmt.relative_offset)]
        args: List[int] = [stmt.stmtid]
        node: Dict[str, Any] = {"tag": stmt.tag}
        args.extend([
            stmt.condition.index(self),
            stmt.ifstmt.index(self),
            stmt.elsestmt.index(self)])
        node["pc-offset"] = stmt.relative_offset
        return self.add(tags, args, node)

    def index_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> int:
        tags: List[str] = [stmt.tag]
        args: List[int] = [stmt.stmtid]
        node: Dict[str, Any] = {"tag": stmt.tag}
        args.extend([instr.index(self) for instr in stmt.instructions])
        return self.add(tags, args, node)

    def index_assign_instr(self, instr: AST.ASTAssign) -> int:
        tags: List[str] = [instr.tag]
        args: List[int] = [instr.instrid]
        node: Dict[str, Any] = {"tag": instr.tag}
        args.extend([instr.lhs.index(self), instr.rhs.index(self)])
        return self.add(tags, args, node)

    def index_call_instr(self, instr: AST.ASTCall) -> int:
        tags: List[str] = [instr.tag]
        args: List[int] = [instr.instrid]
        node: Dict[str, Any] = {"tag": instr.tag}
        lvalindex = -1 if instr.lhs is None else instr.lhs.index(self)
        args.append(lvalindex)
        args.append(instr.tgt.index(self))
        args.extend([arg.index(self) for arg in instr.arguments])
        return self.add(tags, args, node)

    def index_lval(self, lval: AST.ASTLval) -> int:
        tags: List[str] = [lval.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": lval.tag}
        args.extend([lval.lhost.index(self), lval.offset.index(self)])
        return self.add(tags, args, node)

    def index_varinfo(self, vinfo: AST.ASTVarInfo) -> int:
        tags: List[str] = [vinfo.tag, vinfo.vname]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": vinfo.tag, "name": vinfo.vname}
        typindex = vinfo.vtype.index(self) if vinfo.vtype is not None else -1
        parindex = vinfo.parameter if vinfo.parameter is not None else -1
        gaddr = vinfo.globaladdress if vinfo.globaladdress is not None else -1
        args.extend([typindex, parindex, gaddr])
        if vinfo.vdescr is not None:
            node["descr"] = vinfo.vdescr
        return self.add(tags, args, node)

    def index_variable(self, var: AST.ASTVariable) -> int:
        tags: List[str] = [var.tag, var.vname]
        args: List[int] = [var.varinfo.index(self)]
        node: Dict[str, Any] = {"tag": var.tag, "name": var.vname}
        return self.add(tags, args, node)

    def index_memref(self, memref: AST.ASTMemRef) -> int:
        tags: List[str] = [memref.tag]
        args: List[int] = [memref.memexp.index(self)]
        node: Dict[str, Any] = {"tag": memref.tag}
        return self.add(tags, args, node)

    def index_no_offset(self, offset: AST.ASTNoOffset) -> int:
        tags: List[str] = [offset.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": offset.tag}
        return self.add(tags, args, node)

    def index_field_offset(self, offset: AST.ASTFieldOffset) -> int:
        tags: List[str] = [offset.tag, offset.fieldname]
        args: List[int] = [offset.compkey, offset.offset.index(self)]
        node: Dict[str, Any] = {"tag": offset.tag, "fname": offset.fieldname}
        return self.add(tags, args, node)

    def index_index_offset(self, offset: AST.ASTIndexOffset) -> int:
        tags: List[str] = [offset.tag]
        args: List[int] = [
            offset.index_expr.index(self), offset.offset.index(self)]
        node: Dict[str, Any] = {"tag": offset.tag}
        return self.add(tags, args, node)

    def index_integer_constant(self, expr: AST.ASTIntegerConstant) -> int:
        tags: List[str] = [expr.tag, str(expr.cvalue)]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": expr.tag, "value": str(expr.cvalue)}
        return self.add(tags, args, node)

    def index_global_address(self, expr: AST.ASTGlobalAddressConstant) -> int:
        tags: List[str] = [expr.tag, str(expr.cvalue)]
        args: List[int] = [expr.address_expr.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag, "value": str(expr.cvalue)}
        return self.add(tags, args, node)

    def index_string_constant(self, expr: AST.ASTStringConstant) -> int:
        tags: List[str] = [expr.tag, expr.cstr]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": expr.tag, "cstr": expr.cstr}
        if expr.address_expr is not None:
            args.append(expr.address_expr.index(self))
        else:
            args.append(-1)
        if expr.string_address is not None:
            tags.append(expr.string_address)
            node["va"] = expr.string_address
        return self.add(tags, args, node)

    def index_lval_expression(self, expr: AST.ASTLvalExpr) -> int:
        tags: List[str] = [expr.tag]
        args: List[int] = [expr.lval.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag}
        return self.add(tags, args, node)

    def index_substituted_expression(self, expr: AST.ASTSubstitutedExpr) -> int:
        tags: List[str] = [expr.tag, str(expr.assign_id)]
        args: List[int] = [
            expr.super_lval.index(self), expr.substituted_expr.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag, "assigned": str(expr.assign_id)}
        return self.add(tags, args, node)

    def index_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> int:
        tags: List[str] = [expr.tag]
        args: List[int] = [expr.tgt_type.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag}
        return self.add(tags, args, node)

    def index_cast_expression(self, expr: AST.ASTCastExpr) -> int:
        tags: List[str] = [expr.tag]
        args: List[int] = [
            expr.cast_tgt_type.index(self), expr.cast_expr.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag}
        return self.add(tags, args, node)

    def index_unary_expression(self, expr: AST.ASTUnaryOp) -> int:
        tags: List[str] = [expr.tag, expr.op]
        args: List[int] = [expr.exp1.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag, "op": expr.op}
        return self.add(tags, args, node)

    def index_binary_expression(self, expr: AST.ASTBinaryOp) -> int:
        tags: List[str] = [expr.tag, expr.op]
        args: List[int] = [expr.exp1.index(self), expr.exp2.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag, "op": expr.op}
        return self.add(tags, args, node)

    def index_question_expression(self, expr: AST.ASTQuestion) -> int:
        tags: List[str] = [expr.tag]
        args: List[int] = [
            expr.exp1.index(self), expr.exp2.index(self), expr.exp3.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag}
        return self.add(tags, args, node)

    def index_address_of_expression(self, expr: AST.ASTAddressOf) -> int:
        tags: List[str] = [expr.tag]
        args: List[int] = [expr.lval.index(self)]
        node: Dict[str, Any] = {"tag": expr.tag}
        return self.add(tags, args, node)

    def index_void_typ(self, typ: AST.ASTTypVoid) -> int:
        tags: List[str] = [typ.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": typ.tag}
        return self.add(tags, args, node)

    def index_integer_typ(self, typ: AST.ASTTypInt) -> int:
        tags: List[str] = [typ.tag, typ.ikind]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": typ.tag, "ikind": typ.ikind}
        return self.add(tags, args, node)

    def index_float_typ(self, typ: AST.ASTTypFloat) -> int:
        tags: List[str] = [typ.tag, typ.fkind]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": typ.tag, "fkind": typ.fkind}
        return self.add(tags, args, node)

    def index_pointer_typ(self, typ: AST.ASTTypPtr) -> int:
        tags: List[str] = [typ.tag]
        args: List[int] = [typ.tgttyp.index(self)]
        node: Dict[str, Any] = {"tag": typ.tag}
        return self.add(tags, args, node)

    def index_array_typ(self, typ: AST.ASTTypArray) -> int:
        tags: List[str] = [typ.tag]
        args: List[int] = [typ.tgttyp.index(self)]
        node: Dict[str, Any] = {"tag": typ.tag}
        if typ.size_expr is not None:
            args.append(typ.size_expr.index(self))
        else:
            args.append(-1)
        return self.add(tags, args, node)

    def index_fun_typ(self, typ: AST.ASTTypFun) -> int:
        tags: List[str] = [typ.tag]
        args: List[int] = [typ.returntyp.index(self)]
        node: Dict[str, Any] = {"tag": typ.tag}
        args.append(-1 if typ.argtypes is None else typ.argtypes.index(self))
        args.append(1 if typ.is_varargs else 0)
        return self.add(tags, args, node)

    def index_funargs(self, funargs: AST.ASTFunArgs) -> int:
        tags: List[str] = [funargs.tag]
        args: List[int] = [a.index(self) for a in funargs.funargs]
        node: Dict[str, Any] = {"tag": funargs.tag}
        return self.add(tags, args, node)

    def index_funarg(self, funarg: AST.ASTFunArg) -> int:
        tags: List[str] = [funarg.tag, funarg.argname]
        args: List[int] = [funarg.argtyp.index(self)]
        node: Dict[str, Any] = {"tag": funarg.tag, "name": funarg.argname}
        return self.add(tags, args, node)

    def index_named_typ(self, typ: AST.ASTTypNamed) -> int:
        tags: List[str] = [typ.tag, typ.typname]
        args: List[int] = [typ.typdef.index(self)]
        node: Dict[str, Any] = {"tag": typ.tag, "name": typ.typname}
        return self.add(tags, args, node)

    def index_builtin_va_list(self, typ: AST.ASTTypBuiltinVAList) -> int:
        tags: List[str] = [typ.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": typ.tag}
        return self.add(tags, args, node)

    def index_fieldinfo(self, finfo: AST.ASTFieldInfo) -> int:
        tags: List[str] = [finfo.tag, finfo.fieldname]
        args: List[int] = [finfo.fieldtype.index(self), finfo.compkey]
        node: Dict[str, Any] = {"tag": finfo.tag, "name": finfo.fieldname}
        args.append(-1 if finfo.byteoffset is None else finfo.byteoffset)
        return self.add(tags, args, node)

    def index_compinfo(self, cinfo: AST.ASTCompInfo) -> int:
        tags: List[str] = [cinfo.tag, cinfo.cname]
        args: List[int] = [cinfo.ckey, 1 if cinfo.is_union else 0]
        node: Dict[str, Any] = {"tag": cinfo.tag, "name": cinfo.cname}
        args.extend([finfo.index(self) for finfo in cinfo.fieldinfos])
        return self.add(tags, args, node)

    def index_comp_typ(self, typ: AST.ASTTypComp) -> int:
        tags: List[str] = [typ.tag, typ.compname]
        args: List[int] = [typ.compkey]
        node: Dict[str, Any] = {"tag": typ.tag, "cname": typ.compname}
        return self.add(tags, args, node)
