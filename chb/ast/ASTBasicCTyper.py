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


from typing import cast, Optional

from chb.ast.ASTCTyper import ASTCTyper
import chb.ast.ASTNode as AST
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable


class ASTBasicCTyper(ASTCTyper):

    def __init__(self, globalsymboltable: "ASTGlobalSymbolTable") -> None:
        ASTCTyper.__init__(self)
        self._globalsymboltable = globalsymboltable

    @property
    def globalsymboltable(self) -> "ASTGlobalSymbolTable":
        return self._globalsymboltable

    def ctype_lval(self, lval: AST.ASTLval) -> Optional[AST.ASTTyp]:
        hosttype = lval.lhost.ctype(self)
        if hosttype is None:
            return None

        if lval.offset.is_no_offset:
            return hosttype
        elif hosttype.is_array:
            if lval.offset.is_index_offset and lval.offset.offset.is_no_offset:
                return cast(AST.ASTTypArray, hosttype).tgttyp
            else:
                return lval.offset.offset.offset.ctype(self)                
        else:
            return lval.offset.ctype(self)

    def ctype_variable(self, var: AST.ASTVariable) -> Optional[AST.ASTTyp]:
        return var.varinfo.ctype(self)

    def ctype_memref(self, memref: AST.ASTMemRef) -> Optional[AST.ASTTyp]:
        ptrtype = memref.memexp.ctype(self)
        if ptrtype is not None:
            if ptrtype.is_pointer:
                return cast(AST.ASTTypPtr, ptrtype).tgttyp
        return None

    def ctype_no_offset(self, offset: AST.ASTNoOffset) -> Optional[AST.ASTTyp]:
        raise Exception("No offset cannot be typed")

    def ctype_field_offset(
            self, offset: AST.ASTFieldOffset) -> Optional[AST.ASTTyp]:
        if offset.offset.is_no_offset:
            ckey = offset.compkey
            compinfo = self.globalsymboltable.compinfo(ckey)
            fieldinfo = compinfo.fieldinfo(offset.fieldname)
            return fieldinfo.fieldtype
        else:
            return offset.offset.ctype(self)

    def ctype_index_offset(
            self, offset: AST.ASTIndexOffset) -> Optional[AST.ASTTyp]:
        return None
        # raise NotImplementedError("ctype_index_offset: " + str(offset))

    def ctype_integer_constant(
            self, expr: AST.ASTIntegerConstant) -> Optional[AST.ASTTyp]:
        return AST.ASTTypInt(expr.ikind)

    def ctype_floating_point_constant(
            self, expr: AST.ASTFloatingPointConstant) -> Optional[AST.ASTTyp]:
        return AST.ASTTypFloat(expr.fkind)

    def ctype_global_address(
            self, expr: AST.ASTGlobalAddressConstant) -> Optional[AST.ASTTyp]:
        return expr.address_expr.ctype(self)

    def ctype_string_constant(
            self, expr: AST.ASTStringConstant) -> Optional[AST.ASTTyp]:
        return AST.ASTTypPtr(AST.ASTTypInt("ichar"))

    def ctype_lval_expression(
            self, expr: AST.ASTLvalExpr) -> Optional[AST.ASTTyp]:
        return expr.lval.ctype(self)

    def ctype_sizeof_expression(
            self, expr: AST.ASTSizeOfExpr) -> Optional[AST.ASTTyp]:
        return AST.ASTTypInt("iuint")

    def ctype_cast_expression(
            self, expr: AST.ASTCastExpr) -> Optional[AST.ASTTyp]:
        return expr.cast_tgt_type

    def ctype_unary_expression(
            self, expr: AST.ASTUnaryOp) -> Optional[AST.ASTTyp]:
        return expr.exp1.ctype(self)

    def ctype_binary_expression(
            self, expr: AST.ASTBinaryOp) -> Optional[AST.ASTTyp]:
        return expr.exp1.ctype(self)

    def ctype_question_expression(
            self, expr: AST.ASTQuestion) -> Optional[AST.ASTTyp]:
        return expr.exp2.ctype(self)

    def ctype_address_of_expression(
            self, expr: AST.ASTAddressOf) -> Optional[AST.ASTTyp]:
        lvaltyp = expr.lval.ctype(self)
        if lvaltyp is not None:
            return AST.ASTTypPtr(lvaltyp)
        else:
            return None

    def ctype_fieldinfo(self, finfo: AST.ASTFieldInfo) -> Optional[AST.ASTTyp]:
        return finfo.fieldtype

    
        
                
