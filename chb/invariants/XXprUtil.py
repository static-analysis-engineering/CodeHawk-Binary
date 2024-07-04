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
    return [astree.mk_integer_constant(0)]


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
    return [astree.mk_integer_constant(0)]


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
            return astree.mk_address_of(lval)
        else:
            return astree.mk_integer_constant(xc.intvalue)

    else:
        chklogger.logger.error(
            "AST conversion of constant %s not yet supported at address %s",
            str(xc), iaddr)
        return astree.mk_integer_constant(0)


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
        return astree.mk_integer_constant(0)


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
        return astree.mk_integer_constant(0)

    register = vconstvar.register
    optindex = fsig.index_of_register_parameter_location(register)
    if optindex is not None:
        arglvals = astree.function_argument(optindex - 1)
        if len(arglvals) != 1:
            chklogger.logger.error(
                "Encountered multiple arg values for initial register %s at "
                + "address %s",
                str(vconstvar), iaddr)
            return astree.mk_integer_constant(0)
        else:
            return astree.mk_lval_expression(arglvals[0])
    else:
         return astree.mk_named_lval_expression(str(vconstvar))


def xxpr_to_ast_def_exprs(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> List[AST.ASTExpr]:

    chklogger.logger.error(
        "AST def-conversion of expression %s deprecated at address %s",
        str(xpr), iaddr)
    return [astree.mk_integer_constant(0)]


def xvariable_to_ast_def_lval_expression(
        xvar: "XVariable",
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if xvar.is_initial_register_value:
        asmvar = cast("VAuxiliaryVariable", xvar.denotation)
        vinitvar = cast("VInitialRegisterValue", asmvar.auxvar)
        return vinitregister_value_to_ast_lval_expression(
            vinitvar, xdata, iaddr, astree)

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
                return astree.mk_integer_constant(0)
        else:
            chklogger.logger.error(
                "AST def conversion of function return value %s at address %s "
                + "unsuccessfull: no ssa_intro found at callsite %s",
                str(xvar), iaddr, callsite)
            return astree.mk_integer_constant(0)

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
                return astree.mk_vinfo_lval_expression(vinfo)
            else:
                chklogger.logger.error(
                    "Rdef: %s has not yet been introduced at address %s",
                    regrdefs[0], iaddr)
                return astree.mk_integer_constant(0)

        if len(regrdefs) == 0:
            chklogger.logger.error(
                "No rdefs found for %s at address %s", str(reg), iaddr)
            return astree.mk_integer_constant(0)

        else:
            return astree.mk_integer_constant(0)

    else:
        chklogger.logger.error(
            "AST def conversion of variable %s to lval-expression at address "
            + "%s not yet supported",
            str(xvar), iaddr)
        return astree.mk_integer_constant(0)


def xunary_to_ast_def_expr(
        operator: str,
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if operator == "lsh":
        astxpr = xxpr_to_ast_def_expr(xpr, xdata, iaddr, astree)
        mask = astree.mk_integer_constant(0xffff)
        return astree.mk_binary_op("band", astxpr, mask)

    chklogger.logger.error(
        "AST def conversion of unary expression %s at address %s not yet "
        + "supported",
        f"{operator} {xpr}", iaddr)
    return astree.mk_integer_constant(0)


def xbinary_to_ast_def_expr(
        operator: str,
        xpr1: X.XXpr,
        xpr2: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if xpr1.is_var and xpr2.is_constant:
        xvar = cast(X.XprVariable, xpr1).variable
        astxpr1 = xvariable_to_ast_def_lval_expression(xvar, xdata, iaddr, astree)
        astxpr2 = xxpr_to_ast_expr(xpr2, xdata, iaddr, astree)
        if operator in ["plus", "minus"]:
            return astree.mk_binary_expression(operator, astxpr1, astxpr2)

    if xpr1.is_compound and xpr2.is_constant:
        xc = cast(X.XprCompound, xpr1)
        astxpr1 = xcompound_to_ast_def_expr(xc, xdata, iaddr, astree)
        astxpr2 = xxpr_to_ast_expr(xpr2, xdata, iaddr, astree)
        if operator in ["plus", "minus"]:
            return astree.mk_binary_expression(operator, astxpr1, astxpr2)

    chklogger.logger.error(
        "AST def conversion of binary expression %s at address %s not yet "
        + "supported",
        f"{xpr1} {operator} {xpr2}", iaddr)
    return astree.mk_integer_constant(0)


def xcompound_to_ast_def_expr(
        xc: X.XprCompound,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if len(xc.operands) == 1:
        return xunary_to_ast_def_expr(
            xc.operator, xc.operands[0], xdata, iaddr, astree)

    if len(xc.operands) == 2:
        return xbinary_to_ast_def_expr(
            xc.operator, xc.operands[0], xc.operands[1], xdata, iaddr, astree)

    chklogger.logger.error(
        "AST def conversion of compound expression %s at address %s not yet "
        + "supported",
        str(xc), iaddr)
    return astree.mk_integer_constant(0)


def xxpr_to_ast_def_expr(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTExpr:

    if xpr.is_constant:
        return xxpr_to_ast_expr(xpr, xdata, iaddr, astree)

    if xpr.is_var:
        xvar = cast(X.XprVariable, xpr).variable
        return xvariable_to_ast_def_lval_expression(xvar, xdata, iaddr, astree)

    if xpr.is_compound:
        xpr = cast(X.XprCompound, xpr)
        return xcompound_to_ast_def_expr(xpr, xdata, iaddr, astree)

    else:
        chklogger.logger.error(
            "AST def-conversion of expression %s not yet supported "
            + "at address %s",
            str(xpr), iaddr)
        return astree.mk_integer_constant(0)


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
        ctype: Optional[AST.ASTTyp] = None) -> AST.ASTLval:

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


def xvariable_to_ast_lval(
        xv: X.XVariable,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
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
        return astree.mk_temp_lval()

    # register lhs
    elif xv.is_register_variable:
        return astree.mk_ssa_register_variable_lval(str(xv), iaddr, vtype=ctype)

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
            ctype=ctype)

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

    chklogger.logger.error(
        "AST creation of memory dereference for address %s at address %s "
        + "not yet supported",
        str(address), iaddr)
    return astree.mk_temp_lval()


def vfunctionreturn_value_to_ast_lvals(
        vconstvar: "VFunctionReturnValue",
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    chklogger.logger.error(
        "AST conversion of vfunctionreturn_value %s deprecated",
        str(vconstvar))
    return [astree.mk_temp_lval()]
