# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
        xpr: X.XXpr, astree: ASTInterface, anonymous: bool = False) -> AST.ASTExpr:
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

    if all(xpr.is_var for xpr in xprs):
        return xprvariable_list_to_ast_exprs(
            [cast(X.XprVariable, xpr) for xpr in xprs],
            xdata,
            astree,
            anonymous=anonymous)

    return sum((xxpr_to_ast_exprs(xpr, xdata, iaddr, astree) for xpr in xprs), [])


def xxpr_to_ast_exprs(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert an XXpr expression into an AST Expr node."""

    if xpr.is_constant:
        return xconstant_to_ast_exprs(cast(
            X.XprConstant, xpr), xdata, iaddr, astree, anonymous=anonymous)

    elif xpr.is_var:
        xpr = cast(X.XprVariable, xpr)
        if xpr.variable.is_symbolic_value:
            xvar = xpr.variable.get_symbolic_value_expr()
            return xxpr_to_ast_exprs(xvar, xdata, iaddr, astree, size)
        else:
            return xprvariable_to_ast_exprs(
                cast(X.XprVariable, xpr),
                xdata,
                astree,
                size=size,
                anonymous=anonymous)

    elif xpr.is_compound:
        return xcompound_to_ast_exprs(
            cast(X.XprCompound, xpr), xdata, iaddr, astree, anonymous=anonymous)

    else:
        raise UF.CHBError(
            "AST conversion of xxpr " + str(xpr) + " not yet supported")


def xxpr_to_ast_def_exprs(
        xpr: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> List[AST.ASTExpr]:
    """Convert an XXpr expression into an ASTExpr list using reachingdefs."""

    def default() -> List[AST.ASTExpr]:
        return xxpr_to_ast_exprs(xpr, xdata, iaddr, astree)

    if xpr.is_constant:
        return default()

    if xpr.is_function_return_value:
        return default()

    def reg_to_ast_def_exprs(xreg: X.XXpr) -> Optional[AST.ASTExpr]:
        vdefs = xdata.reachingdeflocs_for_s(str(xreg))
        if len(vdefs) == 0:
            astree.add_diagnostic(iaddr + ": no definitions for " + str(xreg))
            return None

        elif len(vdefs) > 1:
            # check if all definitions use the same lhs
            # if so, return that lhs
            vregdefs: List[Tuple[int, AST.ASTExpr]] = []
            vdefined = True
            for vdef in vdefs:
                vregdef = astree.regdefinition(str(vdef), str(xreg))
                if vregdef is None:
                    vdefined = False
                    break
                else:
                    vregdefs.append(vregdef)
            if vdefined:
                vregdef0 = vregdefs[0][1]
                if all(str(vr[1]) == str(vregdef0) for vr in vregdefs):
                    '''
                    for vregdef in vregdefs:
                        astree.astiprovenance.inactivate_lval_defuse_high(
                            vregdef[0], iaddr)
                    '''
                    return vregdef0

                # temporary fix: assume that reaching definitions from allocations do
                # not conflict with the types of alternate reaching definitions; log
                # the fact that these are filtered out.
                nonallocdefs: List[Tuple[int, AST.ASTExpr]] = []
                for vregdef in vregdefs:
                    if str(vregdef[1]).endswith("calloc"):
                        continue
                    nonallocdefs.append(vregdef)
                if len(nonallocdefs) == 1:
                    astree.add_diagnostic(
                        iaddr
                        + " filter out alloc return values for definitions of "
                        + str(xreg)
                        + ": "
                        + ", ".join(str(d) for d in vdefs)
                        + "; "
                        + ", ".join("(" + str(v[0]) + "," + str(v[1]) + ")" for v in vregdefs))
                    return nonallocdefs[0][1]

            equalizedvar: Optional[str] = None
            for d in vdefs:
                if astree.has_variable_intro(str(d)):
                    ivar = astree.get_variable_intro(str(d))
                    if equalizedvar is None:
                        equalizedvar = str(ivar)
                    elif not (equalizedvar == str(ivar)):
                        astree.add_diagnostic(
                            iaddr
                            + ": multiple different introductions: "
                            + str(equalizedvar)
                            + ", "
                            + str(ivar))
                        return None
                    else:
                        pass
                else:
                    astree.add_diagnostic(
                        iaddr
                        + ": multiple definitions; not all of them with varintro: "
                        + str(d))
                    return None

                astree.add_diagnostic(
                    iaddr
                    + ": convert multiple definitions for "
                    + str(xreg)
                    + ": "
                    + ", ".join(str(d) for d in vdefs)
                    + " into varintro "
                    + str(equalizedvar))
                xlval = astree.mk_named_lval_expression(str(equalizedvar))
                return xlval


            astree.add_diagnostic(
                iaddr
                + ": multiple definitions for "
                + str(xreg)
                + ": "
                + ", ".join(str(d) for d in vdefs)
                + "; "
                + ", ".join("(" + str(v[0]) + "," + str(v[1]) + ")" for v in vregdefs))
            return None

        else:
            regdef = astree.regdefinition(str(vdefs[0]), str(xreg))
            if regdef is None:
                astree.add_diagnostic(
                    iaddr
                    + ": no definition found for "
                    + str(xreg)
                    + " at location "
                    + str(vdefs[0]))
                return None

            if astree.expr_has_registers(regdef[1]):
                astree.add_diagnostic(
                    iaddr
                    + ": unable to use "
                    + str(regdef[1])
                    + " for "
                    + str(xreg)
                    + " because of register contained in expr at location "
                    + str(vdefs[0]))
                return None

            else:
                # astree.astiprovenance.inactivate_lval_defuse_high(regdef[0], iaddr)
                return regdef[1]

    def compound_to_ast_def_exprs(xcomp: X.XXpr) -> Optional[AST.ASTExpr]:

        xcomp = cast(X.XprCompound, xcomp)
        xoperands = xcomp.operands
        xoperator = xcomp.operator
        if len(xoperands) == 1:
            x1 = xoperands[0]
            if x1.is_register_variable:
                regdef = reg_to_ast_def_exprs(x1)
                if xoperator in ["lsb", "lsh"]:
                    astree.add_diagnostic(
                        iaddr + ": ast-def: " + str(xcomp))
                    return regdef

                elif regdef is not None:
                    return astree.mk_unary_op(xoperator, regdef)
                else:
                    return None
            elif x1.is_var:
                xpr = cast(X.XprVariable, x1)
                if xpr.variable.is_symbolic_value:
                    xvar = xpr.variable.get_symbolic_value_expr()
                    return xxpr_to_ast_exprs(xvar, xdata, iaddr, astree)[0]

                xvarlvals = xvariable_to_ast_lvals(x1.variable, xdata, astree)
                if len(xvarlvals) == 1:
                    xvarlval = xvarlvals[0]
                    xvarlvaltype = xvarlval.ctype(astree.ctyper)
                    if xvarlvaltype is not None:
                        xvarlvalsize = astree.type_size_in_bytes(xvarlvaltype)
                        if xoperator == "lsb" and xvarlvalsize == 1:
                            return astree.mk_lval_expr(xvarlval)
                        else:
                            astree.add_diagnostic(
                                iaddr
                                + ": unable to convert xvarlval: "
                                + str(xvarlval))
                            return None
                    else:
                        astree.add_diagnostic(
                            iaddr
                            + ": unable to convert xvarlval (no type): "
                            + str(xvarlval))
                        return None
                elif len(xvarlvals) == 4:
                    if xoperator == "lsb":
                        return astree.mk_lval_expr(xvarlvals[0])
                    else:
                        astree.add_diagnostic(
                            iaddr
                            + ": unable to convert x1 (4 lvals): " + str(x1))
                        return None
                else:
                    astree.add_diagnostic(
                        iaddr
                        + ": unable to convert x1 (multiple lvals): " + str(x1))
                    return None

            elif x1.is_compound:
                regdef = compound_to_ast_def_exprs(x1)
                if regdef is not None:
                    if xoperator in ["lsb", "lsh"]:
                        astree.add_diagnostic(
                            iaddr + ": ast_def: " + str(xcomp))
                        return None
                    else:
                        return astree.mk_unary_op(xoperator, regdef)
                else:
                    astree.add_diagnostic(
                        iaddr
                        + ": unable to convert compound x1: "
                        + str(x1))
                    return None
            else:
                astree.add_diagnostic(
                    iaddr
                    + ": unable to convert; other compound expression: "
                    + str(x1))
                return None

        elif len(xoperands) == 2:
            x1 = xoperands[0]
            x2 = xoperands[1]

            regdef1 = xxpr_to_ast_def_exprs(x1, xdata, iaddr, astree)[0]
            regdef2 = xxpr_to_ast_def_exprs(x2, xdata, iaddr, astree)[0]

            if regdef1 is not None and regdef2 is not None:
                regdef1type = regdef1.ctype(astree.ctyper)
                if regdef1type is not None and regdef1type.is_pointer:
                    return xtyped_expr_to_ast_exprs(
                        iaddr,
                        xoperator,
                        regdef1,
                        regdef2,
                        xdata,
                        astree)[0]

                elif regdef1type is not None and regdef1type.is_float:
                    if x2.is_int_constant:
                        fci = cast (X.XprConstant, x2).intvalue
                        f = struct.unpack('f', struct.pack('I', fci))[0]
                        fcst = astree.mk_float_constant(f)
                        return astree.mk_binary_op(xoperator, regdef1, fcst)

                else:

                    # Extract a byte from a 32-bit value
                    if xoperator == "xbyte":
                        if str(regdef1) == "1":
                            mask = astree.mk_integer_constant(0xff00)
                            shift = astree.mk_integer_constant(8)
                            astx1 = astree.mk_binary_op("band", regdef2, mask)
                            astx2 = astree.mk_binary_op("lsr", astx1, shift)
                            return astx2
                        else:
                            return None

                return astree.mk_binary_op(xoperator, regdef1, regdef2)
            else:
                astree.add_diagnostic(
                    iaddr
                    + ": unable to convert compound expression "
                    + str(xpr)
                    + " (regdef1: "
                    + str(regdef1)
                    + ", regdef2: "
                    + str(regdef2)
                    + ")")
                return None

        else:
            return None

    if xpr.is_register_variable:
        regdef = reg_to_ast_def_exprs(xpr)
        if regdef is not None:
            return [regdef]
        else:
            return default()

    elif xpr.is_compound:
        regdef = compound_to_ast_def_exprs(xpr)
        if regdef is not None:
            return [regdef]
        else:
            return default()

    elif xpr.is_var:
        xpr = cast(X.XprVariable, xpr)
        if xpr.variable.is_symbolic_value:
            xvar = xpr.variable.get_symbolic_value_expr()
            return xxpr_to_ast_exprs(xvar, xdata, iaddr, astree)

        xvarlvals = xvariable_to_ast_lvals(xpr.variable, xdata, astree)
        if len(xvarlvals) == 1:
            return [astree.mk_lval_expr(xvarlvals[0])]
        else:
            astree.add_diagnostic(
                iaddr
                + ": unable to convert "
                + str(xpr)
                + ": variable not recognized")
            return default()
    else:
        astree.add_diagnostic(
            iaddr + ": unable to convert " + str(xpr) + ": not recognized")
        return default()


def xconstant_to_ast_exprs(
        xc: X.XprConstant,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert a constant value to an AST Expr node."""

    if xc.is_int_constant:
        gvaddr = astree.globalsymboltable.global_variable_name(hex(xc.intvalue))
        if gvaddr is not None:
            lval = astree.mk_vinfo_lval(gvaddr, anonymous=anonymous)
            return [astree.mk_address_of(lval)]
        else:
            return [astree.mk_integer_constant(xc.intvalue)]

    elif xc.is_bool_constant:
        xconst = cast(XBoolConst, xc.constant)
        if xconst.is_false:
            return [astree.mk_integer_constant(0)]
        else:
            return [astree.mk_integer_constant(1)]

    elif xc.is_random_constant:
        astree.add_diagnostic(iaddr + ": unknown random constant")
        return [astree.mk_integer_constant(0)]

    else:
        raise UF.CHBError(
            "AST conversion of xconstant " + str(xc) + " not yet supported")


def xprvariable_list_to_ast_exprs(
        xvs: List[X.XprVariable],
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:

    lvals = xvariable_list_to_ast_lvals(
        [xv.variable for xv in xvs], xdata, astree, anonymous=anonymous)
    return [astree.mk_lval_expression(lval, anonymous=anonymous) for lval in lvals]


def xprvariable_to_ast_exprs(
        xv: X.XprVariable,
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        ispointer: bool = False,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert a variable to an AST Expr node."""

    def default() -> List[AST.ASTExpr]:
        lvals = xvariable_to_ast_lvals(
            xv.variable, xdata, astree, ispointer=ispointer, size=size, anonymous=anonymous)
        return [astree.mk_lval_expression(
            lval, anonymous=anonymous) for lval in lvals]

    def default_reg(name: str) -> List[AST.ASTExpr]:
        if ispointer:
            vtype = astree.astree.mk_pointer_type(AST.ASTTypVoid())
            lval = astree.mk_register_variable_lval(
                name, vtype=vtype, anonymous=anonymous)
        else:
            lval = astree.mk_register_variable_lval(
                name, anonymous=anonymous)
        return [astree.mk_lval_expression(lval, anonymous=anonymous)]

    if xv.variable.is_tmp:
        return [astree.mk_lval_expression(astree.mk_temp_lval())]

    if xv.variable.is_register_variable:
        xvden = cast("VRegisterVariable", xv.variable.denotation)
        reg = xvden.register
        if reg.is_mips_register:
            mipsreg = cast("MIPSRegister", reg)
            name = "mips_" + mipsreg.name
            return default_reg(name)

        else:
            name = str(xv)
            return default_reg(name)

    if xv.variable.denotation.is_function_return_value:
        fr = cast("VFunctionReturnValue", xv.variable.denotation.auxvar)
        if fr.has_call_target() and str(fr.call_target()) in ["calloc", "malloc", "realloc"]:
            lvalexpr = astree.mk_named_lval_expression(
                str(xv),
                vtype=astree.astree.mk_pointer_type(AST.ASTTypVoid()),
                vdescr="function return value")
            return [lvalexpr]
        else:
            return default()

    if xv.variable.is_initial_memory_value:
        initmemvar = xv.variable.denotation.auxvar
        memvar = initmemvar.variable.denotation
        if memvar.base.is_global:
            lvals = global_variable_to_ast_lvals(memvar.offset, xdata, astree)
            return [astree.mk_lval_expression(lvals[0])]

    return default()


def xtyped_expr_to_ast_exprs(
        iaddr: str,
        op: str,
        op1: AST.ASTExpr,
        op2: AST.ASTExpr,
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Determine if expression needs different representation based on type."""

    op1type = op1.ctype(astree.ctyper)

    if op1type is None:
        raise UF.CHBError("Expression is not typed: " + str(op1))

    if op1type.is_pointer and op2.is_integer_constant and op == "plus":
        op2 = cast(AST.ASTIntegerConstant, op2)
        tgttype = cast(AST.ASTTypPtr, op1type).tgttyp
        if tgttype.is_compound:
            ckey = cast(AST.ASTTypComp, tgttype).compkey
            compinfo = astree.compinfo(ckey)
            fieldoffset = field_at_offset(
                compinfo, op2.cvalue, xdata, astree)
            lval = astree.mk_memref_lval(op1, fieldoffset, anonymous=anonymous)
            return [astree.mk_address_of(lval, anonymous=anonymous)]
        else:
            astree.add_diagnostic(
                iaddr
                + ": conversion to index expression not yet supported: "
                + str(op1)
                + " with type "
                + str(op1type))

    elif op1type.is_pointer:
        tgttype = cast(AST.ASTTypPtr, op1type).tgttyp
        if tgttype.is_array:
            indexoffset = astree.mk_expr_index_offset(op2)
            if op1.is_ast_addressof:
                lval = cast(AST.ASTAddressOf, op1).lval
                lhost = lval.lhost
                loffset = lval.offset
                if loffset.is_no_offset:
                    newlval = astree.mk_lval(lhost, indexoffset)
                    return [astree.mk_address_of(newlval)]

            lval = astree.mk_memref_lval(op1, indexoffset)
            return [astree.mk_address_of(lval, anonymous=anonymous)]

    astree.add_diagnostic(
        iaddr
        + ": unable to convert typed expression: "
        + str(op1)
        + " with type "
        + str(op1type))
    return [astree.mk_binary_expression(op, op1, op2, anonymous=anonymous)]


def xcompound_to_ast_exprs(
        xc: X.XprCompound,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert a compound expression to an AST Expr node."""

    op = xc.operator
    operands = xc.operands

    if len(operands) == 1:
        op1s = xxpr_to_ast_exprs(
            operands[0], xdata, iaddr, astree, anonymous=anonymous)

        if len(op1s) == 1:
            op1 = op1s[0]
            op1type = op1.ctype(astree.ctyper)
            if (
                    op == "lsb"
                    and op1type is not None
                    and astree.type_size_in_bytes(op1type) == 1):
                return [op1]
            elif op == "lsb":
                mask = astree.mk_integer_constant(0xff)
                return [astree.mk_binary_op("band", op1, mask)]
            elif op == "lsh":
                mask = astree.mk_integer_constant(0xffff)
                return [astree.mk_binary_op("band", op1, mask)]
            else:
                return [astree.mk_unary_op(op, op1, anonymous=anonymous)]

        elif len(op1s) == 4 and op == "lsb":
            return [op1s[0]]

        else:
            raise UF.CHBError(
                "Multiple operands to unary operation: "
                + ", ".join(str(x) for x in op1s))

    elif len(operands) == 2:

        if xc.is_stack_address:
            stackoffset = xc.stack_address_offset()
            rhslval = astree.mk_stack_variable_lval(
                stackoffset, anonymous=anonymous)
            return [astree.mk_address_of(rhslval, anonymous=anonymous)]
        else:
            op1s = xxpr_to_ast_exprs(
                operands[0], xdata, iaddr, astree, anonymous=anonymous)
            op2s = xxpr_to_ast_exprs(
                operands[1], xdata, iaddr, astree, anonymous=anonymous)
            if len(op1s) == 1 and len(op2s) == 1:
                op1 = op1s[0]
                op2 = op2s[0]

                # Extract a byte from a 32-bit value
                if op == "xbyte":
                    if str(op1) == "1":
                        mask = astree.mk_integer_constant(0xff00)
                        shift = astree.mk_integer_constant(8)
                        x1 = astree.mk_binary_op("band", op2, mask)
                        x2 = astree.mk_binary_op("lsr", x1, shift)
                        return [x2]

                elif op in ["plus", "minus"]:
                    try:
                        op1type = op1.ctype(astree.ctyper)
                        return xtyped_expr_to_ast_exprs(
                            iaddr, op, op1, op2, xdata, astree, anonymous=anonymous)
                    except Exception:
                        return [astree.mk_binary_expression(
                            op, op1, op2, anonymous=anonymous)]
                elif op in AST.operators:
                    return [astree.mk_binary_expression(
                        op, op1, op2, anonymous=anonymous)]
                else:
                    raise UF.CHBError(
                        "Compound expression with unsupported operator: "
                        + op
                        + " ("
                        + str(op1)
                        + ", "
                        + str(op2)
                        + ")")
            elif op == "band" and len(op2s) == 1 and op2s[0].is_integer_constant:
                mask = cast(AST.ASTIntegerConstant, op2s[0])
                if mask.cvalue == 255 and len(op1s) == 4:
                    # op1 is an array of 4 bytes
                    return [op1s[0]]
                elif mask.cvalue == 0:
                    return [astree.mk_integer_constant(0)]
                elif mask.cvalue > 0 and mask.cvalue < 255:
                    return [astree.mk_binary_op(op, op1s[0], op2s[0])]
                else:
                    raise UF.CHBError(
                        "Multiple operands for one or more operands to binary "
                        + "operation: "
                        + op
                        + " on "
                        + "["
                        + ", ".join(str(x) for x in op1s)
                        + "], ["
                        + ", ".join(str(x) for x in op2s)
                        + "]")

            else:
                raise UF.CHBError(
                    "Multiple operands for one or more operands to binary "
                    + "operation: "
                    + op
                    + " on "
                    + "["
                    + ", ".join(str(x) for x in op1s)
                    + "], ["
                    + ", ".join(str(x) for x in op2s)
                    + "]")

    raise UF.CHBError(
        "AST conversion of compound expression "
        + str(xc)
        + " not yet supported")


def stack_variable_to_ast_lvals(
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        ctype: Optional[AST.ASTTyp] = None,
        anonymous: bool = False) -> List[AST.ASTLval]:
    """TODO: split up."""

    if offset.is_constant_value_offset:
        if size == 2:
            v1 = astree.mk_stack_variable_lval(
                offset.offsetvalue(), vtype=ctype, anonymous=anonymous)
            v2 = astree.mk_stack_variable_lval(
                offset.offsetvalue() + 1, vtype=ctype, anonymous=anonymous)
            return [v1, v2]
        else:
            return [astree.mk_stack_variable_lval(
                offset.offsetvalue(), vtype=ctype, anonymous=anonymous)]

    return [astree.mk_named_lval("stack: " + str(offset), anonymous=anonymous)]


def field_at_offset(
        compinfo: AST.ASTCompInfo,
        offsetvalue: int,
        xdata: "InstrXData",
        astree: ASTInterface) -> AST.ASTOffset:
    (finfo, r) = compinfo.field_at_offset(offsetvalue)

    ftype = finfo.fieldtype
    if ftype.is_typedef:
        ftype = cast(AST.ASTTypNamed, ftype)
        ftype = astree.globalsymboltable.resolve_typedef(ftype.typname)

    if ftype.is_compound:
        fieldfkey = cast(AST.ASTTypComp, ftype).compkey
        fcompinfo = astree.compinfo(fieldfkey)
        foffset = field_at_offset(fcompinfo, r, xdata, astree)
        return astree.mk_field_offset(
            finfo.fieldname, finfo.compkey, offset=foffset)
    elif r == 0:
        return astree.mk_field_offset(finfo.fieldname, finfo.compkey)
    elif ftype.is_array:
        ftype = cast(AST.ASTTypArray, ftype)
        elsize = astree.type_size_in_bytes(ftype.tgttyp)
        if elsize is None:
            raise UF.CHBError(
                "Unable to determine array element size of fieldtype: "
                + str(ftype)
                + " in compinfo "
                + str(compinfo))
        index = r // elsize
        ioffset = astree.mk_scalar_index_offset(index)
        return astree.mk_field_offset(
            finfo.fieldname, finfo.compkey, offset=ioffset)
    else:
        raise UF.CHBError(
            "No field found at offset: "
            + str(offsetvalue)
            + " in struct "
            + compinfo.compname
            + " (Offsets found: "
            + ", ".join(
                (str(f[0])
                 + ":"
                 + str(compinfo.fieldinfo(f[1]).fieldtype)
                 + " "
                 + compinfo.fieldinfo(f[1]).fieldname)
                for f in compinfo.field_offsets.items())
            + ")")


def basevar_variable_to_ast_lvals(
        basevar: "X.XVariable",
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTLval]:

    if offset.is_constant_value_offset:
        offsetvalue = offset.offsetvalue()
        baselvals = xvariable_to_ast_lvals(
            basevar, xdata, astree, anonymous=anonymous)
        if len(baselvals) != 1:
            raise UF.CHBError(
                "Multiple baselvals: "
                + ", ".join(str(b) for b in baselvals))
        baselval = baselvals[0]
        basetype = baselval.ctype(astree.ctyper)

        if basetype is not None:
            if basetype.is_array:
                elttype = cast(AST.ASTTypArray, basetype).tgttyp
                eltsize = astree.type_size_in_bytes(elttype)
                if eltsize is None:
                    raise UF.CHBError(
                        "Unable to determine array element size for "
                        + str(basetype))
                index = offsetvalue // eltsize
                indexoffset = astree.mk_scalar_index_offset(index)
                return [astree.mk_lval(baselval.lhost, indexoffset)]
            elif basetype.is_compound:
                fcompkey = cast(AST.ASTTypComp, basetype).compkey
                compinfo = astree.compinfo(fcompkey)
                fieldoffset = field_at_offset(
                    compinfo, offsetvalue, xdata, astree)
                return [astree.mk_lval(
                    baselval.lhost, fieldoffset, anonymous=anonymous)]
            elif basetype.is_pointer:
                tgttype = cast(AST.ASTTypPtr, basetype).tgttyp
                basexpr = astree.mk_lval_expression(baselval)
                if tgttype.is_scalar:
                    tgtsize = astree.type_size_in_bytes(tgttype)
                    if tgtsize is None:
                        raise UF.CHBError(
                            "Unable to determine size of type " + str(tgttype))
                    index = offsetvalue // tgtsize
                    indexoffset = astree.mk_scalar_index_offset(index)
                    return [astree.mk_lval(
                        baselval.lhost, indexoffset, anonymous=anonymous)]
                elif tgttype.is_compound:
                    try:
                        fcompkey = cast(AST.ASTTypComp, tgttype).compkey
                        compinfo = astree.compinfo(fcompkey)
                        fieldoffset = field_at_offset(
                            compinfo, offsetvalue, xdata, astree)
                        return [astree.mk_memref_lval(
                            basexpr, fieldoffset, anonymous=anonymous)]
                    except Exception as e:
                        astree.add_diagnostic(
                            "Compkey not found for " + str(tgttype) + ": " + str(e))

                elif tgttype.is_void:
                    index = offsetvalue
                    indexoffset = astree.mk_scalar_index_offset(index)
                    return [astree.mk_lval(
                        baselval.lhost, indexoffset, anonymous=anonymous)]
                elif tgttype.is_typedef:
                    tgttype = cast(AST.ASTTypNamed, tgttype)
                    tgttype = tgttype.typdef
                elif offsetvalue == 0:
                    return [astree.mk_memref_lval(basexpr, anonymous=anonymous)]
        else:
            index = offsetvalue
            indexoffset = astree.mk_scalar_index_offset(index)
            return [astree.mk_lval(baselval.lhost, indexoffset, anonymous=anonymous)]

    return [astree.mk_named_lval(str(basevar) + str(offset), anonymous=anonymous)]


def global_variable_to_ast_lvals(
        offset: "VMemoryOffset",
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    if offset.is_constant_value_offset:
        gaddr = hex(offset.offsetvalue())
        gvinfo = astree.globalsymboltable.global_variable_name(gaddr)
        if gvinfo is not None:
            return [astree.mk_vinfo_lval(gvinfo, anonymous=anonymous)]

        gvinfo = astree.globalsymboltable.in_global_variable(
            gaddr, astree.bytesize_calculator)
        if gvinfo is not None:
            igvaddr = gvinfo.globaladdress
            if igvaddr is None:
                raise UF.CHBError(
                    "Internal error in global_variable_to_as_lvals: address")
            gvtype = gvinfo.vtype
            if gvtype is None:
                raise UF.CHBError(
                    "Internal error in global_variable_to_ast_lvals: type")
            if gvtype.is_compound:
                gvtype = cast(AST.ASTTypComp, gvtype)
                gvckey = gvtype.compkey
                gvcompinfo = astree.globalsymboltable.compinfo(gvckey)
                gvoffset = int(gaddr, 16) - igvaddr
                (gvfield, gvfieldoffset) = gvcompinfo.field_at_offset(gvoffset)
                gvfieldtype = gvfield.fieldtype
                if gvfieldtype.is_array:
                    gvfieldtype = cast(AST.ASTTypArray, gvfieldtype)
                    if gvfieldtype.has_constant_size():
                        arraysize = gvfieldtype.size_value()
                        if gvfieldoffset < arraysize:
                            arrayoffset = astree.mk_scalar_index_offset(
                                gvfieldoffset)
                            fieldoffset = astree.mk_field_offset(
                                gvfield.fieldname,
                                gvfield.compkey,
                                offset=arrayoffset)
                            return [astree.mk_vinfo_lval(gvinfo, fieldoffset)]

        gvname = "gv_" + gaddr
        return [astree.mk_named_lval(
            gvname, globaladdress=offset.offsetvalue(), anonymous=anonymous)]

    elif offset.is_constant_offset:
        gaddr = hex(offset.offsetconstant)
        gvinfobase = astree.globalsymboltable.global_variable_name(gaddr)
        if gvinfobase is not None:
            if offset.offset.is_constant_offset:
                coffset = cast("VMemoryOffsetConstantOffset", offset.offset)
                coffsetvalue = coffset.offsetvalue()
                indexoffset = astree.mk_scalar_index_offset(coffsetvalue)
                return [astree.mk_vinfo_lval(gvinfobase, indexoffset)]

            if offset.offset.is_field_offset:
                foffset = cast("VMemoryOffsetFieldOffset", offset.offset)
                fieldoffset = astree.mk_field_offset(
                    foffset.fieldname,
                    foffset.ckey)
                return [astree.mk_vinfo_lval(gvinfobase, fieldoffset)]

            elif offset.offset.is_index_offset:
                ioffset = cast ("VMemoryOffsetIndexOffset", offset.offset)
                indexvar = ioffset.indexvariable
                if indexvar.is_symbolic_value:
                    indexpr = indexvar.get_symbolic_value_expr()
                    astexpr = xxpr_to_ast_exprs(indexpr, xdata, "0x0", astree)[0]
                    indexoffset = astree.mk_expr_index_offset(astexpr)
                    return [astree.mk_vinfo_lval(gvinfobase, indexoffset)]

                astindexvars = xvariable_to_ast_lvals(
                    indexvar, xdata, astree)
                if len(astindexvars) == 1:
                    astindexvar = astindexvars[0]
                    astindexexpr = astree.mk_lval_expr(astindexvar)
                    indexoffset = astree.mk_expr_index_offset(astindexexpr)
                    return [astree.mk_vinfo_lval(gvinfobase, indexoffset)]

        gvname = "gv_" + gaddr + str(offset.offset)
        return [astree.mk_named_lval(
            gvname, globaladdress=offset.offsetconstant, anonymous=anonymous)]


    return [astree.mk_named_lval("gv_" + str(offset), anonymous=anonymous)]


def vmemory_variable_to_ast_lvals(
        xvmem: "VMemoryVariable",
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        ctype: Optional[AST.ASTTyp] = None,
        anonymous: bool = False) -> List[AST.ASTLval]:
    """TODO: split up."""

    if xvmem.base.is_local_stack_frame:
        return stack_variable_to_ast_lvals(
            xvmem.offset,
            xdata,
            astree,
            size=size,
            ctype=ctype,
            anonymous=anonymous)

    elif xvmem.is_basevar_variable:
        return basevar_variable_to_ast_lvals(
            xvmem.basevar,
            xvmem.offset,
            xdata,
            astree,
            size=size,
            anonymous=anonymous)

    elif xvmem.is_global_variable:
        return global_variable_to_ast_lvals(
            xvmem.offset, xdata, astree, anonymous=anonymous)

    return [astree.mk_named_lval(str(xvmem))]


def vinitregister_value_list_to_ast_lvals(
        vconstvars: List["VInitialRegisterValue"],
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    if all(vconstvar.is_argument_value for vconstvar in vconstvars):
        formal_argindices: Set[int] = set([])
        formal_locindices: Set[int] = set([])
        for vconstvar in vconstvars:
            argindex = vconstvar.argument_index()
            (formal, locindices) = astree.get_formal_locindices(argindex)
            formal_argindices.add(formal.argindex)
            for locindex in locindices:
                formal_locindices.add(locindex)

        if len(formal_argindices) == 1:
            # All register arguments refer to the same formal argument
            if len(formal_locindices) == len(formal.arglocs):
                # All components of the formal are covered
                return [astree.mk_formal_lval(formal)]

    return [astree.mk_register_variable_lval(
        str(vconstvar.register), anonymous=anonymous) for vconstvar in vconstvars]


def vinitregister_value_to_ast_lvals(
        vconstvar: "VInitialRegisterValue",
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTLval]:

    fsig = astree.appsignature
    if fsig is not None:
        register = vconstvar.register
        optindex = fsig.index_of_register_parameter_location(register)
        if optindex is not None:
            arglvals = astree.function_argument(optindex - 1)
            if len(arglvals) > 0:
                return arglvals

    if vconstvar.is_argument_value:
        argindex = vconstvar.argument_index()
        if argindex < astree.get_formal_binary_argcount():
            arglvals = astree.function_argument(argindex)
            if len(arglvals) > 0:
                return arglvals

        registername = str(vconstvar.register)
        return [astree.mk_register_variable_lval(
            registername + "_in", registername=registername,
            anonymous=anonymous)]

    elif vconstvar.register.is_stack_pointer:
        return [astree.mk_register_variable_lval("base_sp", anonymous=anonymous)]
    else:
        registername = str(vconstvar.register)
        return [astree.mk_register_variable_lval(
            registername + "_in", registername=registername,
            anonymous=anonymous)]


def vinitmemory_value_to_ast_lvals(
        vconstvar: "VInitialMemoryValue",
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTLval]:

    xvar = vconstvar.variable

    if xvar.is_memory_variable:
        xvmem = cast("VMemoryVariable", xvar.denotation)
        if xvmem.base.is_local_stack_frame:
            offset = xvmem.offset
            if offset.is_constant_value_offset:
                offsetval = offset.offsetvalue()
                if offsetval >= 0 and (offsetval % 4) == 0:
                    argindex = 4 + (offsetval // 4)
                    flvals = astree.function_argument(argindex)
                    if len(flvals) > 0:
                        return flvals

    return xvariable_to_ast_lvals(xvar, xdata, astree, anonymous=anonymous)


def vfunctionreturn_value_to_ast_lvals(
        vconstvar: "VFunctionReturnValue",
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    vtype: Optional[AST.ASTTyp] = None

    if vconstvar.has_call_target():
        calltarget = vconstvar.call_target().name
        if astree.globalsymboltable.has_symbol(calltarget):
            vinfo = astree.globalsymboltable.get_symbol(calltarget)
            if vinfo.vtype is not None:
                vinfotype = cast(AST.ASTTypFun, vinfo.vtype)
                vtype = vinfotype.returntyp

    returnvar = astree.mk_named_variable(str(vconstvar), vtype=vtype)
    return [astree.mk_lval(returnvar, nooffset, anonymous=anonymous)]


def vauxiliary_variable_list_to_ast_lvals(
        xvauxs: List["VAuxiliaryVariable"],
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    if all(xvaux.auxvar.is_initial_register_value for xvaux in xvauxs):
        vconstvars = [
            cast("VInitialRegisterValue", xvaux.auxvar) for xvaux in xvauxs]
        return vinitregister_value_list_to_ast_lvals(
            vconstvars, xdata, astree, anonymous=anonymous)

    return [astree.mk_named_lval(str(xvaux), anonymous=anonymous) for xvaux in xvauxs]


def vauxiliary_variable_to_ast_lvals(
        xvaux: "VAuxiliaryVariable",
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTLval]:

    vconstvar = xvaux.auxvar

    if vconstvar.is_initial_register_value:
        vconstvar = cast("VInitialRegisterValue", vconstvar)
        return vinitregister_value_to_ast_lvals(
            vconstvar, xdata, astree, size=size, anonymous=anonymous)

    elif vconstvar.is_initial_memory_value:
        vconstvar = cast("VInitialMemoryValue", vconstvar)
        return vinitmemory_value_to_ast_lvals(
            vconstvar, xdata, astree, anonymous=anonymous)

    elif vconstvar.is_function_return_value:
        vconstvar = cast("VFunctionReturnValue", vconstvar)
        return vfunctionreturn_value_to_ast_lvals(
            vconstvar, xdata, astree, anonymous=anonymous)

    """TODO: split up."""
    return [astree.mk_named_lval(str(xvaux), anonymous=anonymous)]


def xvariable_list_to_ast_lvals(
        xvs: List[X.XVariable],
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    if all(xv.is_auxiliary_variable for xv in xvs):
        return vauxiliary_variable_list_to_ast_lvals(
            [cast("VAuxiliaryVariable", xv.denotation) for xv in xvs],
            xdata,
            astree,
            anonymous=anonymous)

    return sum(
        (xvariable_to_ast_lvals(
            xv, xdata, astree, anonymous=anonymous) for xv in xvs), [])


def xvariable_to_ast_lvals(
        xv: X.XVariable,
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        ispointer: bool = False,
        ctype: Optional[AST.ASTTyp] = None,
        anonymous: bool = False) -> List[AST.ASTLval]:
    """Convert a CHIF variable to an AST Lval node."""

    if xv.is_tmp:
        return [astree.mk_temp_lval()]

    elif xv.is_register_variable:
        xvden = cast("VRegisterVariable", xv.denotation)
        reg = xvden.register
        if reg.is_mips_register:
            mipsreg = cast("MIPSRegister", reg)
            name = "mips_" + mipsreg.name
        else:
            name = str(xv)

        if xdata.has_ssaval(name):
            ssaval = xdata.get_ssaval(name)
            if ctype is not None:
                asttyp = ctype
            else:
                ssatyp = ssaval.btype
                asttyp = ssatyp.convert(astree.typconverter)
            vdesc = "ssaval:" + name
            vinfo = astree.mk_vinfo(str(ssaval), vtype=asttyp, vdescr=vdesc)
            astlval = astree.mk_vinfo_lval(vinfo)
            # astlval = astree.mk_named_lval(str(ssaval), vtype=asttyp)
            return [astlval]
        else:
            astree.add_diagnostic("No ssa value found for " + name)

        if ispointer:
            vtype = astree.astree.mk_pointer_type(AST.ASTTypVoid())
            astlval = astree.mk_register_variable_lval(name, vtype=vtype, anonymous=anonymous)
        else:
            astlval = astree.mk_register_variable_lval(name, anonymous=anonymous)
        return [astlval]

    elif xv.is_memory_variable:
        xvmem = cast("VMemoryVariable", xv.denotation)
        return vmemory_variable_to_ast_lvals(
            xvmem, xdata, astree, size=size, ctype=ctype, anonymous=anonymous)

    elif xv.is_auxiliary_variable:
        xvaux = cast("VAuxiliaryVariable", xv.denotation)
        return vauxiliary_variable_to_ast_lvals(
            xvaux, xdata, astree, size=size, anonymous=anonymous)

    else:
        return [astree.mk_named_lval(str(xv), anonymous=anonymous)]


def xvar_offset_dereference_lval(
        var: X.XprVariable,
        offset: Optional[X.XXpr],
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTLval:
    """Return an lval associated with a base variable + offset."""

    def default() -> AST.ASTLval:
        addrasts = xprvariable_to_ast_exprs(var, xdata, astree, ispointer=True)
        if len(addrasts) == 0:
            raise UF.CHBError(
                "Error in converting address expression: "
                + str(var))

        elif len(addrasts) > 1:
            raise UF.CHBError(
                "Multiple expressions in convertine address expression: "
                + ", ".join(str(x) for x in addrasts))

        addrast = addrasts[0]
        if offset is not None:
            offsetasts = xxpr_to_ast_exprs(offset, xdata, iaddr, astree)
            if len(offsetasts) == 1:
                addrast = astree.mk_binary_op("plus", addrast, offsetasts[0])

        return astree.mk_memref_lval(addrast)

    vdefs = xdata.reachingdeflocs_for_s(str(var))
    if len(vdefs) == 0:
        return default()

    if len(vdefs) > 1:
        return default()

    regdefxlval = astree.regdefinition(str(vdefs[0]), str(var))
    if regdefxlval is None:
        return default()

    regdef = regdefxlval[1]
    vtype = regdef.ctype(astree.ctyper)
    if vtype is None:
        return default()

    if not vtype.is_pointer:
        return default()

    vtype = cast(AST.ASTTypPtr, vtype)
    vtgttype = vtype.tgttyp
    if not vtgttype.is_compound:
        return default()

    vtgttype = cast(AST.ASTTypComp, vtgttype)
    compinfo = astree.compinfo(vtgttype.compkey)

    if offset is None:
        byte_fieldoffset = 0
    elif offset.is_int_constant:
        byte_fieldoffset = offset.intvalue
    else:
        return default()

    (fieldinfo, suboff) = compinfo.field_at_offset(byte_fieldoffset)
    if not suboff == 0:
        return default()

    fieldoffset = astree.mk_field_offset(fieldinfo.fieldname, vtgttype.compkey)
    return astree.mk_memref_lval(regdef, offset=fieldoffset)


def xmemory_dereference_lval(
        address: X.XXpr,
        xdata: "InstrXData",
        iaddr: str,
        astree: ASTInterface) -> AST.ASTLval:
    """Return an lval associated with a memory address."""

    def default() -> AST.ASTLval:
        addrasts = xxpr_to_ast_def_exprs(address, xdata, iaddr, astree)

        if len(addrasts) == 0:
            raise UF.CHBError(
                "Error in converting address expression: "
                + str(address))

        elif len(addrasts) > 1:
            raise UF.CHBError(
                "Multiple expressions in convertine address expression: "
                + ", ".join(str(x) for x in addrasts))

        addrast = addrasts[0]
        if addrast.is_ast_addressof:
            return cast(AST.ASTAddressOf, addrast).lval
        return astree.mk_memref_lval(addrasts[0])

    if address.is_global_address:
        return default()

    elif address.is_register_variable:
        addresses = xxpr_to_ast_def_exprs(address, xdata, iaddr, astree)
        if len(addresses) == 1:
            addr = addresses[0]
            addrtype = addr.ctype(astree.ctyper)
            if addrtype is not None:
                if addrtype.is_pointer:
                    addrtype = cast(AST.ASTTypPtr, addrtype)
                    addrbasetype = addrtype.tgttyp
                    if addrbasetype.is_compound:
                        addrbasetype = cast(AST.ASTTypComp, addrbasetype)
                        compkey = addrbasetype.compkey
                        compinfo = astree.compinfo(compkey)
                        (field, off) = compinfo.field_at_offset(0)
                        fieldoffset = astree.mk_field_offset(field.fieldname, compkey)
                        return astree.mk_memref_lval(addr, offset=fieldoffset)

            return astree.mk_memref_lval(addresses[0])
        else:
            return default()

    elif address.is_var:
        address = cast(X.XprVariable, address)
        return xvar_offset_dereference_lval(address, None, xdata, iaddr, astree)

    elif address.is_compound:
        address = cast(X.XprCompound, address)
        if not (len(address.operands) == 2):
            return default()

        op1 = address.operands[0]
        op2 = address.operands[1]

        if op1.is_var:
            op1 = cast(X.XprVariable, op1)
            return xvar_offset_dereference_lval(op1, op2, xdata, iaddr, astree)

        if not op1.is_global_address:
            return default()

        gvinfo = astree.globalsymboltable.global_variable_name(str(op1))
        if gvinfo is None:
            return default()

        gvtype = gvinfo.vtype
        if gvtype is None:
            return default()

        if gvtype.is_array:
            gvtype = cast(AST.ASTTypArray, gvtype)
            eltype = gvtype.tgttyp
            eltypsize = astree.type_size_in_bytes(eltype)
            if eltypsize is None:
                raise UF.CHBError(
                    "Unable to determine size of array element type "
                    + str(eltype))

            if not op2.is_compound:
                return default()

            op2 = cast(X.XprCompound, op2)
            if (not len(op2.operands) == 2):
                return default()

            op2_1 = op2.operands[0]
            op2_2 = op2.operands[1]

            if op2_1.is_int_const_value(eltypsize):

                indexexprs = xxpr_to_ast_exprs(op2_2, xdata, iaddr, astree)
                if len(indexexprs) == 1:
                    offset = astree.mk_expr_index_offset(indexexprs[0])
                    lval = astree.mk_vinfo_lval(gvinfo, offset=offset)
                    return lval

    return default()
