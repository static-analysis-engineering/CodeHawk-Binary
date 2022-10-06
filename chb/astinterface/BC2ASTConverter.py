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
"""Converter from the BC types (CIL) to the AST types."""

from typing import Dict, List

from chb.ast.ASTIndexer import ASTIndexer
import chb.ast.ASTNode as AST
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable

from chb.bctypes.BCCompInfo import BCCompInfo
import chb.bctypes.BCConstant as BCC
from chb.bctypes.BCConverter import BCConverter
from chb.bctypes.BCEnumInfo import BCEnumInfo
from chb.bctypes.BCEnumItem import BCEnumItem
import chb.bctypes.BCExp as BCE
from chb.bctypes.BCFieldInfo import BCFieldInfo
from chb.bctypes.BCFiles import BCFiles
from chb.bctypes.BCFunArgs import BCFunArgs, BCFunArg
from chb.bctypes.BCLHost import BCHostVar, BCHostMem
from chb.bctypes.BCLval import BCLval
from chb.bctypes.BCOffset import BCNoOffset, BCFieldOffset, BCIndexOffset
import chb.bctypes.BCTyp as BCT
from chb.bctypes.BCVarInfo import BCVarInfo

import chb.util.fileutil as UF

bc2ast_operators: Dict[str, str] = {
    "div": "div",
    "minusa": "minus",
    "mult": "mult"
    }


def convert_bc_operator(op: str) -> str:
    if op in bc2ast_operators:
        return bc2ast_operators[op]
    else:
        raise UF.CHBError("BC operator " + op + " not found")


class BC2ASTConverter(BCConverter):

    def __init__(
            self,
            globalstore: BCFiles,
            symboltable: ASTGlobalSymbolTable) -> None:
        BCConverter.__init__(self)
        self._globalstore = globalstore
        self._symboltable = symboltable
        self._compinfos_referenced: Dict[int, BCCompInfo] = {}
        self._enuminfos_referenced: Dict[str, BCEnumInfo] = {}
        self._newcompinfos: Dict[int, BCCompInfo] = {}
        self._newenuminfos: Dict[str, BCEnumInfo] = {}
        self._structsizes: Dict[int, int] = {}

    @property
    def globalstore(self) -> BCFiles:
        return self._globalstore

    @property
    def symboltable(self) -> ASTGlobalSymbolTable:
        return self._symboltable

    @property
    def compinfos_referenced(self) -> Dict[int, BCCompInfo]:
        return self._compinfos_referenced

    @property
    def enuminfos_referenced(self) -> Dict[str, BCEnumInfo]:
        return self._enuminfos_referenced

    @property
    def structsizes(self) -> Dict[int, int]:
        return self._structsizes

    def get_lvalid(self) -> int:
        return self.symboltable.get_lvalid(None)

    def get_exprid(self) -> int:
        return self.symboltable.get_exprid(None)

    def add_compinfo_reference(self, cinfo: BCCompInfo) -> None:
        if cinfo.ckey not in self.compinfos_referenced:
            self._newcompinfos.setdefault(cinfo.ckey, cinfo)

    def add_enuminfo_reference(self, einfo: BCEnumInfo) -> None:
        if einfo.ename not in self.enuminfos_referenced:
            self._newenuminfos.setdefault(einfo.ename, einfo)

    def initialize_compinfos(self) -> None:
        if len(self._newcompinfos) == 0:
            return
        else:
            for (key, cinfo) in self._newcompinfos.items():
                if key not in self._compinfos_referenced:
                    self._compinfos_referenced[key] = cinfo
            self._newcompinfos = {}
        for cinfo in self.compinfos_referenced.values():
            cinfo.convert(self)
        self.initialize_compinfos()

    def initialize_enuminfos(self, startset: List[BCEnumInfo] = []) -> None:
        if len(startset) > 0:
            for einfo in startset:
                if einfo.ename not in self._enuminfos_referenced:
                    self._enuminfos_referenced[einfo.ename] = einfo

        if len(self._newenuminfos) > 0:
            for (ename, einfo) in self._newenuminfos.items():
                if ename not in self._enuminfos_referenced:
                    self._enuminfos_referenced[ename] = einfo
            self._newenuminfos = {}

        for einfo in self.enuminfos_referenced.values():
            einfo.convert(self)

    def convert_lval(self, lval: BCLval) -> AST.ASTLval:
        lhost = lval.lhost.convert(self)
        offset = lval.offset.convert(self)
        lvalid = self.get_lvalid()
        return AST.ASTLval(lvalid, lhost, offset)  # TBD

    def convert_varinfo(self, vinfo: BCVarInfo) -> AST.ASTVarInfo:
        vtype = vinfo.vtype.convert(self)
        return AST.ASTVarInfo(vinfo.vname, vtype)

    def convert_variable(self, var: BCHostVar) -> AST.ASTVariable:
        if self.globalstore.has_vardecl(var.varname):
            bcvinfo = self.globalstore.vardecl(var.varname)
            vinfo = bcvinfo.convert(self)
            return AST.ASTVariable(vinfo)
        else:
            raise UF.CHBError(
                "No global variable declaration found for " + var.varname)

    def convert_memref(self, memref: BCHostMem) -> AST.ASTMemRef:
        return AST.ASTMemRef(memref.memexp.convert(self))

    def convert_no_offset(self, offset: BCNoOffset) -> AST.ASTNoOffset:
        return AST.ASTNoOffset()

    def convert_field_offset(self, offset: BCFieldOffset) -> AST.ASTFieldOffset:
        suboffset = offset.suboffset.convert(self)
        return AST.ASTFieldOffset(offset.fieldname, offset.compkey, suboffset)

    def convert_index_offset(self, offset: BCIndexOffset) -> AST.ASTIndexOffset:
        suboffset = offset.suboffset.convert(self)
        return AST.ASTIndexOffset(offset.exp.convert(self), suboffset)

    def convert_integer_constant(self, c: BCC.BCCInt64) -> AST.ASTIntegerConstant:
        exprid = self.get_exprid()
        return AST.ASTIntegerConstant(exprid, c.value)

    def convert_string_constant(self, c: BCC.BCStr) -> AST.ASTStringConstant:
        exprid = self.get_exprid()
        return AST.ASTStringConstant(exprid, None, c.strvalue, None)

    def convert_lval_expression(self, x: BCE.BCExpLval) -> AST.ASTLvalExpr:
        exprid = self.get_exprid()
        return AST.ASTLvalExpr(exprid, x.lval.convert(self))

    def convert_sizeof_expression(self, x: BCE.BCExpSizeOf) -> AST.ASTSizeOfExpr:
        exprid = self.get_exprid()
        return AST.ASTSizeOfExpr(exprid, x.typ.convert(self))

    def convert_cast_expression(self, x: BCE.BCExpCastE) -> AST.ASTCastExpr:
        asttyp = x.typ.convert(self)
        astexp = x.exp.convert(self)
        exprid = self.get_exprid()
        return AST.ASTCastExpr(exprid, asttyp, astexp)

    def convert_unary_expression(self, x: BCE.BCExpUnOp) -> AST.ASTUnaryOp:
        op = convert_bc_operator(x.operator)
        exprid = self.get_exprid()
        return AST.ASTUnaryOp(exprid, op, x.exp.convert(self))

    def convert_binary_expression(self, x: BCE.BCExpBinOp) -> AST.ASTBinaryOp:
        op = convert_bc_operator(x.operator)
        exprid = self.get_exprid()
        return AST.ASTBinaryOp(
            exprid, op, x.exp1.convert(self), x.exp2.convert(self))

    def convert_question_expression(
            self, x: BCE.BCExpQuestion) -> AST.ASTQuestion:
        exprid = self.get_exprid()
        return AST.ASTQuestion(
            exprid,
            x.exp1.convert(self),
            x.exp2.convert(self),
            x.exp3.convert(self))

    def convert_address_of_expression(
            self, x: BCE.BCExpAddressOf) -> AST.ASTAddressOf:
        exprid = self.get_exprid()
        return AST.ASTAddressOf(exprid, x.lval.convert(self))

    def convert_void_typ(self, t: BCT.BCTypVoid) -> AST.ASTTypVoid:
        return AST.ASTTypVoid()

    def convert_integer_typ(self, t: BCT.BCTypInt) -> AST.ASTTypInt:
        return AST.ASTTypInt(t.ikind)

    def convert_float_typ(self, t: BCT.BCTypFloat) -> AST.ASTTypFloat:
        return AST.ASTTypFloat(t.fkind)

    def convert_pointer_typ(self, t: BCT.BCTypPtr) -> AST.ASTTypPtr:
        return AST.ASTTypPtr(t.tgttyp.convert(self))

    def convert_array_typ(self, t: BCT.BCTypArray) -> AST.ASTTypArray:
        astsize = None if t.size_expr is None else t.size_expr.convert(self)
        return AST.ASTTypArray(t.tgttyp.convert(self), astsize)

    def convert_fun_typ(self, t: BCT.BCTypFun) -> AST.ASTTypFun:
        # astfunargs = None if t.argtypes is None else t.argtypes.convert(self)
        if t.argtypes is None:
            # use for now until signatures have been updated
            astfunargs = AST.ASTFunArgs([])
        else:
            astfunargs = t.argtypes.convert(self)
        returntype = t.returntype.convert(self)
        return AST.ASTTypFun(returntype, astfunargs, t.is_vararg)

    def convert_funargs(self, args: BCFunArgs) -> AST.ASTFunArgs:
        return AST.ASTFunArgs([a.convert(self) for a in args.funargs])

    def convert_funarg(self, arg: BCFunArg) -> AST.ASTFunArg:
        return AST.ASTFunArg(arg.name, arg.typ.convert(self))

    def convert_named_typ(self, t: BCT.BCTypNamed) -> AST.ASTTypNamed:
        namedtype = AST.ASTTypNamed(t.tname, t.typedef.ttype.convert(self))
        return namedtype

    def convert_builtin_va_list(
            self, t: BCT.BCTypBuiltinVaList) -> AST.ASTTypBuiltinVAList:
        return AST.ASTTypBuiltinVAList()

    def convert_comp_typ(self, t: BCT.BCTypComp) -> AST.ASTTypComp:
        self.add_compinfo_reference(t.compinfo)
        return AST.ASTTypComp(t.compname, t.compkey)

    def convert_enum_typ(self, t: BCT.BCTypEnum) -> AST.ASTTypEnum:
        self.add_enuminfo_reference(t.enuminfo)
        return AST.ASTTypEnum(t.ename, t.enuminfo.ekind)

    def convert_enuminfo(self, einfo: BCEnumInfo) -> AST.ASTEnumInfo:
        if self.symboltable.has_enuminfo(einfo.ename):
            return self.symboltable.enuminfo(einfo.ename)
        else:
            astitems: List[AST.ASTEnumItem] = []
            for eitem in einfo.enumitems:
                astitems.append(eitem.convert(self))
            asteinfo = AST.ASTEnumInfo(einfo.ename, astitems, einfo.ekind)
            self.symboltable.add_enuminfo(asteinfo)
            return asteinfo

    def convert_enumitem(self, eitem: BCEnumItem) -> AST.ASTEnumItem:
        astexpr = eitem.itemexpr.convert(self)
        return AST.ASTEnumItem(eitem.itemname, astexpr)

    def convert_compinfo(self, cinfo: BCCompInfo) -> AST.ASTCompInfo:
        if self.symboltable.has_compinfo(cinfo.ckey):
            return self.symboltable.compinfo(cinfo.ckey)
        else:
            astfields: List[AST.ASTFieldInfo] = []
            bcfieldoffsets = cinfo.fieldoffsets()
            for (offset, bcfinfo) in bcfieldoffsets:
                astfinfo = AST.ASTFieldInfo(
                    bcfinfo.fieldname,
                    bcfinfo.fieldtype.convert(self),
                    bcfinfo.ckey,
                    byteoffset=offset)
                astfields.append(astfinfo)
            astcinfo = AST.ASTCompInfo(
                cinfo.cname, cinfo.ckey, astfields, is_union=cinfo.is_union)
            self._structsizes[cinfo.ckey] = cinfo.byte_size()
            return astcinfo

    def convert_fieldinfo(self, finfo: BCFieldInfo) -> AST.ASTFieldInfo:
        return AST.ASTFieldInfo(
            finfo.fieldname, finfo.fieldtype.convert(self), finfo.ckey)
