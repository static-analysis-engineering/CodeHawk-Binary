# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
from codecs import decode
import struct

from typing import cast, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XConstant import XBoolConst
from chb.invariants.XVariable import XVariable
import chb.invariants.XXpr as X

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.app.InstrXData import InstrXData
    from chb.invariants.InvariantFact import InvariantFact
    from chb.invariants.VAssemblyVariable import (
        VMemoryVariable, VAuxiliaryVariable, VRegisterVariable)
    from chb.invariants.VConstantValueVariable import (
        VInitialRegisterValue, VInitialMemoryValue, VFunctionReturnValue,
        SymbolicValue)
    from chb.invariants.VMemoryOffset import (
        VMemoryOffset,
        VMemoryOffsetConstantOffset,
        VMemoryOffsetFieldOffset,
        VMemoryOffsetIndexOffset)
    from chb.mips.MIPSRegister import MIPSRegister


def is_struct_field_address(xpr: X.XXpr, astree: ASTInterface) -> bool:
    """Return true if the expression is the address of a known struct."""

    if xpr.is_int_constant:
        return astree.is_struct_field_address(xpr.intvalue)

    return False


def xxpr_to_struct_field_address_expr(
        xpr: X.XXpr, astree: ASTInterface, anonymous: bool = False
) -> AST.ASTExpr:
    """Return a struct field as an address expression."""

    if not is_struct_field_address(xpr, astree):
        raise UF.CHBError("Expression " + str(xpr) + " is not a struct field")

    return astree.get_struct_field_address(xpr.intvalue)


def xxpr_list_to_ast_exprs(
        xprs: List[X.XXpr],
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:

    chklogger.logger.error(
        "AST conversion of expr list %s deprecated at address %s",
        ", ".join(str(x) for x in xprs), iaddr)
    return [astree.mk_temp_lval_expression()]


def xxpr_to_ast_exprs(
                xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTExpr]:

    chklogger.logger.error(
        "AST conversion of expr %s deprecated at address %s",
        str(xpr), iaddr)
    return [astree.mk_temp_lval_expression()]


def xconstant_to_ast_expr(
        xc: X.XprConstant,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        anonymous: bool = False) -> AST.ASTExpr:
    """Convert a constant value to an ASTExpr node."""

    if xc.is_int_constant:
        # check if this value represents a global variable
        gvaddr = astree.globalsymboltable.global_variable_name(
            hex(xc.intvalue))
        if gvaddr is not None:
            lval = astree.mk_vinfo_lval(gvaddr, anonymous=anonymous)
            gvaddrtype = gvaddr.ctype(astree.ctyper)
            if gvaddrtype is not None and gvaddrtype.is_array:
                # array already is an address
                return astree.mk_lval_expr(lval)
            else:
                return astree.mk_address_of(lval)
        else:
            return astree.mk_integer_constant(xc.intvalue)

    else:
        chklogger.logger.error(
            "AST conversion of constant %s not yet supported at address %s",
            str(xc), iaddr)
        return astree.mk_temp_lval_expression()


def xxpr_to_ast_expr(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> AST.ASTExpr:

    if xpr.is_constant:
        return xconstant_to_ast_expr(
            cast(X.XprConstant, xpr), xdata, iaddr, astree, anonymous=anonymous)

    else:
        chklogger.logger.error(
            "AST conversion of expression %s not yet supported at address %s",
            str(xpr), iaddr)
        return astree.mk_temp_lval_expression()


def vinitregister_value_to_ast_lval_expression(
        vconstvar: "VInitialRegisterValue",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    fsig = astree.appsignature
    if fsig is None:
        chklogger.logger.error(
            "Unable to judge initial register %s value without app signature "
            + "at address %s",
            str(vconstvar), iaddr)
        return astree.mk_temp_lval_expression()

    register = vconstvar.register
    optindex = fsig.index_of_register_parameter_location(register)
    if optindex is not None:
        arglvals = astree.function_argument(optindex - 1)
        if len(arglvals) != 1:
            chklogger.logger.error(
                "Encountered multiple arg values for initial register %s at "
                + "address %s",
                str(vconstvar), iaddr)
            return astree.mk_temp_lval_expression()
        else:
            return astree.mk_lval_expression(arglvals[0])
    else:
         return astree.mk_named_lval_expression(str(vconstvar))


def vreturn_deref_value_to_ast_lval_expression(
        basevar: "XVariable",
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if not offset.is_constant_value_offset:
        chklogger.logger.error(
            "Non-constant offset: %s not yet supported at address %s",
            str(offset), iaddr)
        return astree.mk_temp_lval_expression()

    coff = offset.offsetvalue()
    if basevar.is_function_return_value:
        asmvar = cast("VAuxiliaryVariable", basevar.denotation)
        vreturnvar = cast("VFunctionReturnValue", asmvar.auxvar)
        callsite = vreturnvar.callsite
        if callsite in astree.ssa_intros:
            if len(astree.ssa_intros[callsite]) == 1:
                vinfo = list(astree.ssa_intros[callsite].values())[0]
                vexpr = astree.mk_vinfo_lval_expression(vinfo)
                return astree.mk_memref_expr(vexpr)

    chklogger.logger.error(
        "AST conversion of dereferenced return value %s not yet supported at "
        + "address %s",
        str(basevar), iaddr)

    return astree.mk_temp_lval_expression()


def vglobal_variable_value_to_ast_lval_expression(
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4) -> AST.ASTExpr:

    if offset.is_constant_value_offset:
        gaddr = offset.offsetconstant
        hexgaddr = hex(gaddr)
        vinfo = astree.global_addresses.get(hexgaddr, None)
        if vinfo is not None:
            return astree.mk_vinfo_lval_expression(vinfo)
        else:
            name = "gv_" + hex(gaddr)
            return astree.mk_global_variable_expr(name, globaladdress = gaddr)

    # element of global array
    if offset.is_constant_offset and offset.offset.is_constant_value_offset:
        hexgaddr = hex(offset.offsetconstant)
        vinfo = astree.global_addresses.get(hexgaddr, None)

        if vinfo is None:
            chklogger.logger.error(
                "Conversion of global value %s at address %s not yet supported",
                str(offset), iaddr)
            return astree.mk_temp_lval_expression()

        vtype = vinfo.vtype
        if vtype is None:
            chklogger.logger.error(
                ("Conversion of global value %s without type at address %s not "
                 + " yet supported"),
                str(offset), iaddr)
            return astree.mk_temp_lval_expression()

        if vtype.is_array:
            vtype = cast(AST.ASTTypArray, vtype)
            elttype = vtype.tgttyp
            eltoffset = offset.offset.offsetconstant
            elttypesize = astree.type_size_in_bytes(elttype)
            if elttypesize is not None:
                if not (elttypesize == size):
                    chklogger.logger.warning(
                        ("Load size (%d) is different from element size (%d) "
                         + "in array access of %s at address %s"),
                        size, elttypesize, str(offset), iaddr)
                arrayindex = eltoffset // elttypesize
                indexoffset = astree.mk_scalar_index_offset(arrayindex)
                return astree.mk_vinfo_lval_expression(vinfo, indexoffset)

    chklogger.logger.error(
        "Conversion of global value %s at address %s not yet supported",
        str(offset), iaddr)
    return astree.mk_temp_lval_expression()


def vargument_deref_value_to_ast_lval_expression(
        basevar: "XVariable",
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if not offset.is_constant_value_offset:
        chklogger.logger.error(
            "Non-constant offset: %s not yet supported at address %s",
            str(offset), iaddr)
        return astree.mk_temp_lval_expression()

    coff = offset.offsetvalue()
    if basevar.is_initial_register_value:
        asmvar = cast("VAuxiliaryVariable", basevar.denotation)
        vinitvar = cast("VInitialRegisterValue", asmvar.auxvar)
        xinitarg = vinitregister_value_to_ast_lval_expression(
            vinitvar, xdata, iaddr, astree)
        argtype = xinitarg.ctype(astree.ctyper)
        if argtype is None:
            chklogger.logger.error(
                "Untyped dereferenced argument value %s not yet supported at "
                + "address %s",
                str(xinitarg), iaddr)
            return astree.mk_temp_lval_expression()

        if argtype.is_pointer:
            tgttype = cast(AST.ASTTypPtr, argtype).tgttyp
            if tgttype.is_compound:

                compkey = cast(AST.ASTTypComp, tgttype).compkey
                if not astree.has_compinfo(compkey):
                    chklogger.logger.error(
                        ("Encountered compinfo key without definition in "
                         + "symbol table: %d"),
                        compkey)
                    return astree.mk_integer_constant(0)

                compinfo = astree.compinfo(compkey)
                (field, restoffset) = compinfo.field_at_offset(coff)
                if restoffset > 0:
                    chklogger.logger.error(
                        "Rest offset in memory dereference not yet handled at "
                        + "%s: %s",
                        iaddr, str(restoffset))
                    return astree.mk_integer_constant(0)
                foffset = astree.mk_field_offset(field.fieldname, compkey)
                return astree.mk_memref_expr(xinitarg, offset = foffset)

    chklogger.logger.error(
        "AST conversion of argument deref value: %s not yet handled at %s",
        str(basevar), iaddr)

    return astree.mk_temp_lval_expression()


def vinitmemory_value_to_ast_lval_expression(
        vconstvar: "VInitialMemoryValue",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4) -> AST.ASTExpr:

    if vconstvar.is_global_value:
        avar = vconstvar.variable.denotation
        return vglobal_variable_value_to_ast_lval_expression(
            avar.offset, xdata, iaddr, astree, size=size)

    if vconstvar.is_argument_deref_value:
        avar = vconstvar.variable.denotation
        return vargument_deref_value_to_ast_lval_expression(
            avar.basevar, avar.offset, xdata, iaddr, astree)

    if vconstvar.is_function_return_deref_value:
        avar = vconstvar.variable.denotation
        return vreturn_deref_value_to_ast_lval_expression(
            avar.basevar, avar.offset, xdata, iaddr, astree)

    chklogger.logger.error(
        "AST Conversion of vinitmemory value %s not yet supported at address %s",
        str(vconstvar), iaddr)

    return astree.mk_temp_lval_expression()


def xxpr_to_ast_def_exprs(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> List[AST.ASTExpr]:

    chklogger.logger.error(
        "AST def-conversion of expression %s deprecated at address %s",
        str(xpr), iaddr)
    return [astree.mk_temp_lval_expression()]


def xvariable_to_ast_def_lval_expression(
        xvar: "XVariable",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4) -> AST.ASTExpr:

    if xvar.is_initial_register_value:
        asmvar = cast("VAuxiliaryVariable", xvar.denotation)
        vrinitvar = cast("VInitialRegisterValue", asmvar.auxvar)
        return vinitregister_value_to_ast_lval_expression(
            vrinitvar, xdata, iaddr, astree)

    if xvar.is_initial_memory_value:
        if xdata.function.has_var_disequality(iaddr, xvar):
            chklogger.logger.error(
                "Initial memory value %s has changed and cannot be used at %s",
                str(xvar), iaddr)
            return astree.mk_temp_lval_expression()

        asmvar = cast("VAuxiliaryVariable", xvar.denotation)
        vminitvar = cast("VInitialMemoryValue", asmvar.auxvar)
        return vinitmemory_value_to_ast_lval_expression(
            vminitvar, xdata, iaddr, astree, size=size)

    if xvar.is_function_return_value:
        asmvar = cast("VAuxiliaryVariable", xvar.denotation)
        freturnvar = cast("VFunctionReturnValue", asmvar.auxvar)
        callsite = freturnvar.callsite
        if callsite in astree.ssa_intros:
            if len(astree.ssa_intros[callsite]) == 1:
                vinfo = list(astree.ssa_intros[callsite].values())[0]
                return astree.mk_vinfo_lval_expression(vinfo)
            else:
                chklogger.logger.error(
                    "Call site with multiple ssa variables at address %s "
                    + "not yet supported",
                    callsite)
                return astree.mk_temp_lval_expression()
        else:
            chklogger.logger.error(
                "AST def conversion of function return value %s at address %s "
                + "unsuccessfull: no ssa_intro found at callsite %s",
                str(xvar), iaddr, callsite)
            return astree.mk_temp_lval_expression()

    if xvar.is_symbolic_expr_value:
        asmvar = cast("VAuxiliaryVariable", xvar.denotation)
        symxvar = cast("SymbolicValue", asmvar.auxvar)
        symxpr = symxvar.expr
        return xxpr_to_ast_def_expr(symxpr, xdata, iaddr, astree)

    if xvar.is_register_variable:
        reg = cast("VRegisterVariable", xvar.denotation).register
        rdefs = xdata.reachingdefs
        regrdefs: List[str] = []
        for rdef in rdefs:
            if rdef is not None:
                if (str(rdef.vardefuse.variable)) == str(reg):
                    for sym in rdef.vardefuse.symbols:
                        if str(sym) not in regrdefs:
                            regrdefs.append(str(sym))
        if len(regrdefs) > 0:
            if (
                    regrdefs[0] in astree.ssa_intros
                    and str(reg) in astree.ssa_intros[regrdefs[0]]):
                vinfo = astree.ssa_intros[regrdefs[0]][str(reg)]
                ssavalue = astree.get_ssa_value(vinfo.vname)
                if ssavalue is not None:
                    return ssavalue
                else:
                    return astree.mk_vinfo_lval_expression(vinfo)
            else:
                chklogger.logger.error(
                    "Rdef: %s has not yet been introduced at address %s",
                    regrdefs[0], iaddr)
                return astree.mk_temp_lval_expression()

        if len(regrdefs) == 0:
            chklogger.logger.error(
                "No rdefs found for %s at address %s", str(reg), iaddr)
            return astree.mk_temp_lval_expression()

        else:
            return astree.mk_temp_lval_expression()

    else:
        chklogger.logger.error(
            "AST def conversion of variable %s to lval-expression at address "
            + "%s not yet supported",
            str(xvar), iaddr)
        return astree.mk_temp_lval_expression()


def xunary_to_ast_def_expr(
        operator: str,
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4) -> AST.ASTExpr:

    if operator == "lsh":
        astxpr = xxpr_to_ast_def_expr(xpr, xdata, iaddr, astree)
        mask = astree.mk_integer_constant(0xffff)
        return astree.mk_binary_op("band", astxpr, mask)

    if operator == "lsb":
        astxpr = xxpr_to_ast_def_expr(xpr, xdata, iaddr, astree, size=1)
        if size == 1:
            return astxpr

        mask = astree.mk_integer_constant(0xff)
        xprtype = astxpr.ctype(astree.ctyper)
        if xprtype is None:
            return astree.mk_binary_op("band", astxpr, mask)

        xprtypesize = astree.type_size_in_bytes(xprtype)
        if xprtypesize is None:
            return astree.mk_binary_op("band", astxpr, mask)

        if xprtypesize == 1:
            return astxpr

        else:
            return astree.mk_binary_op("band", astxpr, mask)


    chklogger.logger.error(
        "AST def conversion of unary expression %s at address %s not yet "
        + "supported",
        f"{operator} {xpr}", iaddr)
    return astree.mk_temp_lval_expression()


def xbinary_to_ast_def_expr(
        operator: str,
        xpr1: X.XXpr,
        xpr2: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    def default() -> AST.ASTExpr:
        astxpr1 = xxpr_to_ast_def_expr(xpr1, xdata, iaddr, astree)
        astxpr2 = xxpr_to_ast_def_expr(xpr2, xdata, iaddr, astree)
        if operator in ["plus", "minus", "mult", "lsl", "eq", "ne", "gt", "le"]:
            return astree.mk_binary_expression(operator, astxpr1, astxpr2)
        else:
            chklogger.logger.error(
                "AST def conversion of binary expression %s, %s with operator %s "
                + "at address %s not yet supported",
                str(xpr1), str(xpr2), operator, iaddr)
            return astree.mk_temp_lval_expression()

    if xpr1.is_var and xpr2.is_constant:
        xvar = cast(X.XprVariable, xpr1).variable
        astxpr1 = xvariable_to_ast_def_lval_expression(xvar, xdata, iaddr, astree)
        astxpr2 = xxpr_to_ast_expr(xpr2, xdata, iaddr, astree)
        if operator in ["plus", "minus"]:
            return astree.mk_binary_expression(operator, astxpr1, astxpr2)
        else:
            return default()

    if xpr1.is_compound and xpr2.is_constant:
        xc = cast(X.XprCompound, xpr1)
        astxpr1 = xcompound_to_ast_def_expr(xc, xdata, iaddr, astree)
        astxpr2 = xxpr_to_ast_expr(xpr2, xdata, iaddr, astree)
        if operator in ["plus", "minus"]:
            return astree.mk_binary_expression(operator, astxpr1, astxpr2)
        else:
            return default()

    return default()


def xcompound_to_ast_def_expr(
        xc: X.XprCompound,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4) -> AST.ASTExpr:

    if len(xc.operands) == 1:
        return xunary_to_ast_def_expr(
            xc.operator, xc.operands[0], xdata, iaddr, astree, size=size)

    if len(xc.operands) == 2:
        return xbinary_to_ast_def_expr(
            xc.operator, xc.operands[0], xc.operands[1], xdata, iaddr, astree)

    chklogger.logger.error(
        "AST def conversion of compound expression %s at address %s not yet "
        + "supported",
        str(xc), iaddr)
    return astree.mk_temp_lval_expression()


def xxpr_to_ast_def_expr(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4) -> AST.ASTExpr:

    if xpr.is_constant:
        return xxpr_to_ast_expr(xpr, xdata, iaddr, astree)

    if xpr.is_var:
        xvar = cast(X.XprVariable, xpr).variable
        return xvariable_to_ast_def_lval_expression(
            xvar, xdata, iaddr, astree, size=size)

    if xpr.is_compound:
        xpr = cast(X.XprCompound, xpr)
        return xcompound_to_ast_def_expr(xpr, xdata, iaddr, astree, size=size)

    else:
        chklogger.logger.error(
            "AST def-conversion of expression %s not yet supported "
            + "at address %s",
            str(xpr), iaddr)
        return astree.mk_temp_lval_expression()


def xvariable_to_ast_lvals(
        xv: X.XVariable,
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        ispointer: bool = False,
        ctype: Optional[AST.ASTTyp] = None,
        anonymous: bool = False) -> List[AST.ASTLval]:

    chklogger.logger.error(
        "AST conversion to lvals deprecated for %s", str(xv))

    if str(xv) == "D31":
        raise UF.CHBError("AST conversion to lvals deprecated")
    return [astree.mk_temp_lval()]


def stack_variable_to_ast_lval(
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4,
        ctype: Optional[AST.ASTTyp] = None,
        memaddr: Optional[X.XXpr] = None) -> AST.ASTLval:

    if offset.is_constant_value_offset:
        if size == 4:
            return astree.mk_stack_variable_lval(
                offset.offsetvalue(), vtype=ctype)

        chklogger.logger.error(
            "Stack variable with size %d not yet supported at addresss %s",
            size, iaddr)
        return astree.mk_temp_lval()

    chklogger.logger.error(
        "Stack variable with non-constant offset %s not yet supported at "
        + "address %s",
        str(offset), iaddr)
    return astree.mk_temp_lval()


def global_variable_to_ast_lval(
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4,
        ctype: Optional[AST.ASTTyp] = None,
        memaddr: Optional[X.XXpr] = None) -> AST.ASTLval:

    # global variable without additional offset
    if offset.is_constant_value_offset:
        hexgaddr = hex(offset.offsetvalue())
        vinfo = astree.global_addresses.get(hexgaddr, None)
        if vinfo is not None:
            return astree.mk_vinfo_lval(vinfo)

        else:
            name = "gv_" + hexgaddr
            return astree.mk_named_lval(
                name, globaladdress = offset.offsetvalue())

    if offset.is_constant_offset:
        hexgaddr = hex(offset.offsetconstant)
        vinfo = astree.global_addresses.get(hexgaddr, None)
        if offset.offset.is_index_offset and vinfo is not None:
            indexoffset = cast("VMemoryOffsetIndexOffset", offset.offset)
            indexvar = indexoffset.indexvariable
            offsetxpr = xvariable_to_ast_def_lval_expression(
                indexvar, xdata, iaddr, astree)
            astoffset = astree.mk_expr_index_offset(offsetxpr)
            return astree.mk_vinfo_lval(vinfo, astoffset)

    chklogger.logger.error(
        ("Conversion of global ast lval for address %s at address %s "
         + "not yet supported"),
        str(offset), iaddr)
    return astree.mk_temp_lval()


def xvariable_to_ast_lval(
        xv: X.XVariable,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        memaddr: Optional[X.XXpr] = None,
        rhs: Optional[X.XXpr] = None,
        size: int = 4,
        ispointer: bool = False,
        ctype: Optional[AST.ASTTyp] = None) -> AST.ASTLval:
    """Returns a high-level lvalue for an lhs.

    Note. this function should not be used to compute the lvalue of an
    lval-expr. The reason is that a high-level register lhs is converted
    to an ssa value, while a high-level register that is part of some rhs
    should be delegated to its reaching definitions, and thus should stay
    confined to functions dealing with rhs values.
    """

    # unknown memory value
    if xv.is_tmp:
        if memaddr is not None:
            return xmemory_dereference_lval(memaddr, xdata, iaddr, astree)

        chklogger.logger.error(
            "Conversion of memory lhs unsuccessful due to unknown memory address "
            + "at address " + iaddr)
        return astree.mk_temp_lval()

    # register lhs
    elif xv.is_register_variable:
        if ctype is None:
            bctype = xdata.function.register_lhs_type(iaddr, str(xv))
            if bctype is not None:
                ctype = bctype.convert(astree.typconverter)
        if rhs is not None and rhs.is_constant:
            astrhs = xxpr_to_ast_expr(rhs, xdata, iaddr, astree)
        else:
            astrhs = None
        return astree.mk_ssa_register_variable_lval(
            str(xv), iaddr, vtype=ctype, ssavalue=astrhs)

    # stack variable lhs
    elif (
            xv.is_memory_variable
            and cast("VMemoryVariable",
                     xv.denotation).base.is_local_stack_frame):
        xvmem = cast("VMemoryVariable", xv.denotation)
        return stack_variable_to_ast_lval(
            xvmem.offset,
            xdata,
            iaddr,
            astree,
            size=size,
            ctype=ctype,
            memaddr=memaddr)

    elif (
            xv.is_memory_variable
            and cast("VMemoryVariable",
                     xv.denotation).base.is_global):
        xvmem = cast("VMemoryVariable", xv.denotation)
        return global_variable_to_ast_lval(
            xvmem.offset,
            xdata,
            iaddr,
            astree,
            size=size,
            ctype=ctype,
            memaddr=memaddr)

    else:
        chklogger.logger.error(
            "AST conversion of lval %s at address %s not yet supported",
            str(xv), iaddr)
        return astree.mk_temp_lval()


def xmemory_dereference_lval(
        address: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTLval:

    xaddr = xxpr_to_ast_def_expr(address, xdata, iaddr, astree)
    if xaddr.is_ast_binary_op:
        xaddr = cast(AST.ASTBinaryOp, xaddr)
        if xaddr.exp1.is_ast_lval_expr:
            xlval = cast(AST.ASTLvalExpr, xaddr.exp1)
            xlvaltype = xlval.ctype(astree.ctyper)
            if xlvaltype is not None and xlvaltype.is_array:
                astoffset = astree.mk_expr_index_offset(xaddr.exp2)
                lvalhost = xlval.lval.lhost
                return astree.mk_lval(lvalhost, astoffset)

    chklogger.logger.error(
        "AST creation of memory dereference for address %s (%s) at address %s "
        + "not yet supported",
        str(address), str(xaddr), iaddr)
    return astree.mk_temp_lval()


def xmemory_dereference_to_ast_def_expr(
        address: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    hl_addr = xxpr_to_ast_def_expr(address, xdata, iaddr, astree)
    hl_addr_type = hl_addr.ctype(astree.ctyper)
    if hl_addr_type is None:
        return astree.mk_memref_expr(hl_addr)

    if hl_addr_type.is_pointer:
        tgttype = cast(AST.ASTTypPtr, hl_addr_type).tgttyp
        if tgttype.is_compound:

            # Identify field offsets
            compkey = cast(AST.ASTTypComp, tgttype).compkey
            if not astree.has_compinfo(compkey):
                chklogger.logger.error(
                    ("Encountered compinfo key without definition in symbol "
                     + " table: %d"),
                    compkey)
                return astree.mk_memref_expr(hl_addr)

            compinfo = astree.compinfo(compkey)
            fieldoffset = 0
            baseaddr = hl_addr
            if hl_addr.is_ast_binary_op:
                hl_addr = cast(AST.ASTBinaryOp, hl_addr)
                if not hl_addr.op == "plus":
                    chklogger.logger.error(
                        "Encountered address expression with op %s",
                        hl_addr.op)
                    return astree.mk_memref_expr(hl_addr)

                if not hl_addr.exp2.is_integer_constant:
                    chklogger.logger.warning(
                        "Non-constant field offset not yet supported: %s",
                        str(hl_addr.exp2))
                    return astree.mk_memref_expr(hl_addr)

                fieldoffset = cast(AST.ASTIntegerConstant, hl_addr.exp2).cvalue
                baseaddr = hl_addr.exp1

            (field, restoffset) = compinfo.field_at_offset(fieldoffset)
            if restoffset > 0:
                chklogger.logger.warning(
                    "Rest offset in memory dereference not yet handled at %s: %s",
                    iaddr, str(hl_addr))
            foffset = astree.mk_field_offset(field.fieldname, compkey)
            return astree.mk_memref_expr(baseaddr, offset = foffset)

    chklogger.logger.warning(
        "Unexpected type for address in memory dereference: %s",
        str(hl_addr_type))
    return astree.mk_memref_expr(hl_addr)


def vfunctionreturn_value_to_ast_lvals(
        vconstvar: "VFunctionReturnValue",
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    chklogger.logger.error(
        "AST conversion of vfunctionreturn_value %s deprecated",
        str(vconstvar))
    return [astree.mk_temp_lval()]
