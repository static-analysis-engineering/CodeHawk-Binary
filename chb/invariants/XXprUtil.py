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

from typing import cast, List, Optional, Sequence, Set, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XVariable import XVariable
import chb.invariants.XXpr as X

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.InstrXData import InstrXData
    from chb.invariants.InvariantFact import InvariantFact
    from chb.invariants.VAssemblyVariable import (
        VMemoryVariable, VAuxiliaryVariable, VRegisterVariable)
    from chb.invariants.VConstantValueVariable import (
        VInitialRegisterValue, VInitialMemoryValue, VFunctionReturnValue)
    from chb.invariants.VMemoryOffset import VMemoryOffset
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
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:

    if all(xpr.is_var for xpr in xprs):
        return xprvariable_list_to_ast_exprs(
            [cast(X.XprVariable, xpr) for xpr in xprs],
            xdata,
            astree,
            anonymous=anonymous)

    return sum((xxpr_to_ast_exprs(xpr, xdata, astree) for xpr in xprs), [])


def xxpr_to_ast_exprs(
        xpr: X.XXpr,
        xdata: "InstrXData",
        astree: ASTInterface,
        size: int = 4,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert an XXpr expression into an AST Expr node."""

    if xpr.is_constant:
        return xconstant_to_ast_exprs(cast(
            X.XprConstant, xpr), xdata, astree, anonymous=anonymous)

    elif xpr.is_var:
        return xprvariable_to_ast_exprs(
            cast(X.XprVariable, xpr),
            xdata,
            astree,
            size=size,
            anonymous=anonymous)

    elif xpr.is_compound:
        return xcompound_to_ast_exprs(
            cast(X.XprCompound, xpr), xdata, astree, anonymous=anonymous)

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
        return xxpr_to_ast_exprs(xpr, xdata, astree)

    if xpr.is_constant:
        return default()

    def reg_to_ast_def_exprs(xreg: X.XXpr) -> Optional[AST.ASTExpr]:
        vdefs = xdata.reachingdeflocs_for_s(str(xreg))
        if len(vdefs) == 0:
            astree.add_diagnostic(iaddr + ": no definitions for " + str(xreg))
            return None

        elif len(vdefs) > 1:
            astree.add_diagnostic(iaddr + ": multiple definitions for " + str(xreg))
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
                astree.astiprovenance.inactivate_lval_defuse_high(regdef[0], iaddr)
                return regdef[1]

    def compound_to_ast_def_exprs(xcomp: X.XXpr) -> Optional[AST.ASTExpr]:
        xcomp = cast(X.XprCompound, xcomp)
        xoperands = xcomp.operands
        xoperator = xcomp.operator
        if len(xoperands) == 1:
            x1 = xoperands[0]
            if x1.is_register_variable:
                regdef = reg_to_ast_def_exprs(x1)
                if regdef is not None:
                    return astree.mk_unary_op(xoperator, regdef)
                else:
                    return None
            elif x1.is_compound:
                regdef = compound_to_ast_def_exprs(x1)
                if regdef is not None:
                    return astree.mk_unary_op(xoperator, regdef)
                else:
                    return None
            else:
                return None

        elif len(xoperands) == 2:
            x1 = xoperands[0]
            x2 = xoperands[1]
            if x1.is_register_variable:
                regdef1 = reg_to_ast_def_exprs(x1)
            elif x1.is_compound:
                regdef1 = compound_to_ast_def_exprs(x1)
            elif x1.is_constant:
                regdef1 = xxpr_to_ast_exprs(x1, xdata, astree)[0]
            else:
                regdef1 = None

            if x2.is_register_variable:
                regdef2 = reg_to_ast_def_exprs(x2)
            elif x2.is_compound:
                regdef2 = compound_to_ast_def_exprs(x2)
            elif x2.is_constant:
                regdef2 = xxpr_to_ast_exprs(x2, xdata, astree)[0]
            else:
                regdef2 = None

            if regdef1 is not None and regdef2 is not None:
                return astree.mk_binary_op(xoperator, regdef1, regdef2)
            else:
                astree.add_diagnostic(
                    iaddr + ": unable to convert " + str(xpr))
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

    else:
        astree.add_diagnostic(
            iaddr + ": unable to convert " + str(xpr) + ": not recognized")
        return default()


def xconstant_to_ast_exprs(
        xc: X.XprConstant,
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert a constant value to an AST Expr node."""

    if xc.is_int_constant:
        return [astree.mk_integer_constant(xc.intvalue)]

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
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert a variable to an AST Expr node."""

    def default() -> List[AST.ASTExpr]:
        lvals = xvariable_to_ast_lvals(
            xv.variable, xdata, astree, size=size, anonymous=anonymous)
        return [astree.mk_lval_expression(
            lval, anonymous=anonymous) for lval in lvals]

    def default_reg() -> List[AST.ASTExpr]:
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
            return default_reg()

        else:
            name = str(xv)

    return default()


def xtyped_expr_to_ast_exprs(
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

    if op1type.is_pointer and op2.is_integer_constant:
        op2 = cast(AST.ASTIntegerConstant, op2)
        tgttype = cast(AST.ASTTypPtr, op1type).tgttyp
        if tgttype.is_compound:
            ckey = cast(AST.ASTTypComp, tgttype).compkey
            compinfo = astree.compinfo(ckey)
            fieldoffset = field_at_offset(
                compinfo, op2.cvalue, xdata, astree)
            lval = astree.mk_memref_lval(op1, fieldoffset, anonymous=anonymous)
            return [astree.mk_address_of(lval, anonymous=anonymous)]

    return [astree.mk_binary_expression(op, op1, op2, anonymous=anonymous)]


def xcompound_to_ast_exprs(
        xc: X.XprCompound,
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTExpr]:
    """Convert a compound expression to an AST Expr node."""

    op = xc.operator
    operands = xc.operands

    if len(operands) == 1:
        op1s = xxpr_to_ast_exprs(operands[0], xdata, astree, anonymous=anonymous)

        if len(op1s) == 1:
            op1 = op1s[0]
            if op == "lsb":
                mask = astree.mk_integer_constant(0xff)
                return [astree.mk_binary_op("band", op1, mask)]
            if op == "lsh":
                mask = astree.mk_integer_constant(0xff00)
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
                operands[0], xdata, astree, anonymous=anonymous)
            op2s = xxpr_to_ast_exprs(
                operands[1], xdata, astree, anonymous=anonymous)
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
                            op, op1, op2, xdata, astree, anonymous=anonymous)
                    except:
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

    if finfo.fieldtype.is_compound:
        fieldfkey = cast(AST.ASTTypComp, finfo.fieldtype).compkey
        fcompinfo = astree.compinfo(fieldfkey)
        foffset = field_at_offset(fcompinfo, r, xdata, astree)
        return astree.mk_field_offset(
            finfo.fieldname, finfo.compkey, offset=foffset)
    elif r == 0:
        return astree.mk_field_offset(finfo.fieldname, finfo.compkey)
    elif finfo.fieldtype.is_array:
        ftype = cast(AST.ASTTypArray, finfo.fieldtype)
        elsize = astree.type_size_in_bytes(ftype.tgttyp)
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
                    index = offsetvalue // tgtsize
                    indexoffset = astree.mk_scalar_index_offset(index)
                    return [astree.mk_lval(
                        baselval.lhost, indexoffset, anonymous=anonymous)]
                elif tgttype.is_compound:
                    fcompkey = cast(AST.ASTTypComp, tgttype).compkey
                    compinfo = astree.compinfo(fcompkey)
                    fieldoffset = field_at_offset(
                        compinfo, offsetvalue, xdata, astree)
                    return [astree.mk_memref_lval(
                        basexpr, fieldoffset, anonymous=anonymous)]
                elif tgttype.is_void:
                    index = offsetvalue
                    indexoffset = astree.mk_scalar_index_offset(index)
                    return [astree.mk_lval(
                        baselval.lhost, indexoffset, anonymous=anonymous)]
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

    if vconstvar.is_argument_value:
        argindex = vconstvar.argument_index()
        arglvals = astree.function_argument(argindex)
        if len(arglvals) > 0:
            return arglvals
        else:
            register = str(vconstvar.register)
            return [astree.mk_register_variable_lval(
                register + "_in", registername=register, anonymous=anonymous)]

    elif vconstvar.register.is_stack_pointer:
        return [astree.mk_register_variable_lval("base_sp", anonymous=anonymous)]
    else:
        register = str(vconstvar.register)
        return [astree.mk_register_variable_lval(
            register + "_in", registername=register, anonymous=anonymous)]


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
                    return flvals

    return xvariable_to_ast_lvals(xvar, xdata, astree, anonymous=anonymous)


def vfunctionreturn_value_to_ast_lvals(
        vconstvar: "VFunctionReturnValue",
        xdata: "InstrXData",
        astree: ASTInterface,
        anonymous: bool = False) -> List[AST.ASTLval]:

    vtype: Optional[AST.ASTTyp] = None

    if vconstvar.has_call_target():
        calltarget = str(vconstvar.call_target())
        if astree.has_symbol(calltarget):
            vinfo = astree.get_symbol(calltarget)
            vtype = vinfo.vtype

    return [astree.mk_returnval_variable_lval(
        vconstvar.callsite, vtype, anonymous=anonymous)]


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
        return [astree.mk_register_variable_lval(name, anonymous=anonymous)]

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
        astree: ASTInterface) -> AST.ASTLval:
    """Return an lval associated with a base variable + offset."""

    def default() -> AST.ASTLval:
        addrasts = xprvariable_to_ast_exprs(var, xdata, astree)
        if len(addrasts) == 0:
            raise UF.CHBError(
                "Error in converting address expression: "
                + str(var))

        elif len(addrasts) > 1:
            raise UF.CHBError(
                "Multiple expressions in convertine address expression: "
                + ", ".join(str(x) for x in addrasts))

        return astree.mk_memref_lval(addrasts[0])

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

        return astree.mk_memref_lval(addrasts[0])

    if address.is_global_address:
        return default()

    elif address.is_register_variable:
        addresses = xxpr_to_ast_def_exprs(address, xdata, iaddr, astree)
        if len(addresses) == 1:
            return astree.mk_memref_lval(addresses[0])
        else:
            return default()

    elif address.is_var:
        address = cast(X.XprVariable, address)
        return xvar_offset_dereference_lval(address, None, xdata, astree)

    elif address.is_compound:
        address = cast(X.XprCompound, address)
        if not (len(address.operands) == 2):
            return default()

        op1 = address.operands[0]
        op2 = address.operands[1]

        if op1.is_var:
            op1 = cast(X.XprVariable, op1)
            return xvar_offset_dereference_lval(op1, op2, xdata, astree)

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

            if not op2.is_compound:
                return default()

            op2 = cast(X.XprCompound, op2)
            if (not len(op2.operands) == 2):
                return default()

            op2_1 = op2.operands[0]
            op2_2 = op2.operands[1]

            if op2_1.is_int_const_value(eltypsize):

                indexexprs = xxpr_to_ast_exprs(op2_2, xdata, astree)
                if len(indexexprs) == 1:
                    offset = astree.mk_expr_index_offset(indexexprs[0])
                    lval = astree.mk_vinfo_lval(gvinfo, offset=offset)
                    return lval

    return default()
