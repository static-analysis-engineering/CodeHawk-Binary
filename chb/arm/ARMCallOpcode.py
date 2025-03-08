# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2025  Aarno Labs LLC
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

from typing import (
    Any, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.api.CallTarget import AppTarget
from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.ASTIUtil import assign_type_compatible

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr, XprCompound
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.bctypes.BCTyp import BCTypFun
    from chb.invariants.VarInvariantFact import ReachingDefFact
    from chb.invariants.VAssemblyVariable import VRegisterVariable
    from chb.invariants.VConstantValueVariable import VFunctionReturnValue
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr, XprConstant, XprVariable


class ARMCallOpcodeXData(ARMOpcodeXData):
    """
    xdata format: a:x[2n]xr[n]dh, call   (n arguments)
    -------------------------------------------------
    xprs[0..2n-1]: (arg location expr, arg value expr) * n
    xprs[2n]: call target expression
    rdefs[0..n-1]: arg location reaching definitions
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            xdata: InstrXData,
            ixd: "InterfaceDictionary") -> None:
        ARMOpcodeXData.__init__(self, xdata)
        self._ixd = ixd

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def argument_count(self) -> int:
        argcount = self._xdata.call_target_argument_count()
        if argcount is None:
            chklogger.logger.error(
                "No argument count found for call")
            return 0
        return argcount

    @property
    def arguments(self) -> List["XXpr"]:
        argcount = self.argument_count
        arguments: List["XXpr"] = []
        for i in range(argcount):
            x = self._xdata.xprs_r[i]
            if x is None:
                x = self._xdata.xprs_r[i + argcount]
                if x is None:
                    raise UF.CHBError(
                        "Unexpected None-value call argument at index "
                        + str(i))
            arguments.append(x)
        return arguments

    @property
    def argumentxvars(self) -> List["XXpr"]:
        argcount = self.argument_count
        return [x for x in self._xdata.xprs_r[argcount:2 * argcount]
                if x is not None]

    @property
    def calltarget(self) -> "CallTarget":
        return self._xdata.call_target(self._ixd)

    @property
    def annotation(self) -> str:
        tgt = str(self.calltarget)
        args = ", ".join(str(x) for x in self.arguments)
        call = "call " + str(tgt) + "(" + args + ")"
        return self.add_instruction_condition(call)


class ARMCallOpcode(ARMOpcode):
    """Generic call functionality, covers BL and BLX.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary

    (if call target is not known):
    xdata format: a:xxxxx
    ---------------------
    vars[0]: return value variable
    xprs[0..3]: expressions for R0-R3
    xprs[4]: target expression
    rdefs[0]: target reaching definition
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return [ARMCallOpcodeXData(xdata, self.ixd).vrd]

    def argument_count(self, xdata: InstrXData) -> int:
        return ARMCallOpcodeXData(xdata, self.ixd).argument_count

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in self.arguments(xdata)]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return ARMCallOpcodeXData(xdata, self.ixd).arguments

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) >= 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMCallOpcodeXData(xdata, self.ixd)
        return xd.annotation

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    def ast_call_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            name: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        if xdata.has_inlined_call_target():
            chklogger.logger.info("Inlined call omitted at %s", iaddr)
            return ([], [])

        xd = ARMCallOpcodeXData(xdata, self.ixd)

        annotations: List[str] = [iaddr, "BL"]

        # low-level call data

        lhs = xd.vrd
        tgt = self.opargs[0]

        if not lhs.is_register_variable:
            raise UF.CHBError(
                "Expected a register variable for call lhs at "
                + iaddr
                + " but found "
                + str(lhs))

        lhsreg = cast("VRegisterVariable", lhs.denotation)
        ll_lhs = astree.mk_register_variable_lval(str(lhsreg))
        (ll_tgt, _, _) = tgt.ast_rvalue(astree)

        xprs = xd.arguments
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        # high-level call data

        hl_tgt = ll_tgt
        hl_lhs: Optional[AST.ASTLval] = None

        astfntype: Optional[AST.ASTTyp] = None

        # construct high-level target
        finfo = xdata.function.finfo
        if finfo.has_call_target_info(iaddr):
            ctinfo = finfo.call_target_info(iaddr)
            ftype = ctinfo.target_interface.bctype
            if ftype is not None:
                try:
                    astfntype = ftype.convert(astree.typconverter)
                except UF.CHBError as e:
                    chklogger.logger.warning(
                        "Type conversion of function type was unsuccessful: %s",
                        str(e))

            if xdata.is_bx_call:
                # indirect call
                hl_tgt = XU.xxpr_to_ast_def_expr(xprs[-1], xdata, iaddr, astree)
            else:
                fname = ctinfo.target_interface.name
                if astree.globalsymboltable.has_symbol(fname):
                    tgtvinfo = astree.globalsymboltable.get_symbol(fname)
                    hl_tgt = astree.mk_vinfo_lval_expression(tgtvinfo)
                else:
                    gaddr: int = 0
                    if fname.startswith("sub_"):
                        gaddr = int("0x" + fname[4:], 16)
                    else:
                        if tgt.is_absolute:
                            tgtaddr = cast(ARMAbsoluteOp, tgt.opkind)
                            gaddr = int(tgtaddr.address.get_hex(), 16)
                    hl_tgt = astree.mk_global_variable_expr(
                        fname, globaladdress=gaddr, vtype=astfntype)

            if ftype is not None and ftype.is_function:
                ftype = cast("BCTypFun", ftype)
                rtype = ftype.returntype
            else:
                rtype = ctinfo.target_interface.signature.returntype
            asttype = rtype.convert(astree.typconverter)

            # Create a lhs even if it is not used, because the ssa value
            # introduced may be used in the available expressions.
            hl_lhs = XU.xvariable_to_ast_lval(
                lhs, xdata, iaddr, astree, ctype=asttype)

            if rtype.is_void or defuses[0] is None:
                chklogger.logger.info(
                    "Unused: introduced ssa-variable: %s for return value of %s "
                    + "at address %s",
                    str(hl_lhs), str(hl_tgt), iaddr)
                hl_lhs = None

        # argument data

        argcount = xd.argument_count

        ll_args: List[AST.ASTExpr] = []
        hl_args: List[AST.ASTExpr] = []

        if argcount > 0:
            if astfntype is None:
                astargtypes: List[Optional[AST.ASTTyp]] = [None] * argcount
            else:
                astfntype = cast(AST.ASTTypFun, astfntype)
                astfunargs = astfntype.argtypes
                if astfunargs is None:
                    astargtype = [None] * argcount
                else:
                    astargtypes = [a.argtyp for a in astfunargs.funargs]

                # add extra elements for vararg arguments
                if len(astargtypes) < argcount:
                    astargtypes += ([None] * (argcount - len(astargtypes)))

            xargs = xd.arguments
            xvarargs = xd.argumentxvars
            if len(rdefs) >= argcount:
                llrdefs = rdefs[:argcount]
                # x represents the (invariant-enhanced) argument value.
                # xv represents the location of the argument, which can be
                #  either a register, or a stack location, where the stack
                #  location is represented by an expression of the form
                #  (sp + n), with n is the offset from the current stackpointer
                #  in bytes (note: not the stackpointer at function entry).
                # rdef represents the reaching definition for the argument
                #  location.
                for (x, xv, rdef, argtype) in zip(
                        xargs, xvarargs, llrdefs, astargtypes):

                    # low-level argument

                    if xv.is_register_variable:
                        xv = cast("XprVariable", xv)
                        xvar = cast("VRegisterVariable", xv.variable.denotation)
                        xreg = xvar.register
                        ll_arglval = astree.mk_register_variable_lval(str(xreg))
                        ll_arg = astree.mk_lval_expression(ll_arglval)
                    elif xv.is_compound:
                        xv = cast("XprCompound", xv)
                        if not (xv.operator == "plus"):
                            chklogger.logger.warning(
                                "Expected positive stack offset in call ll_arg: "
                                + "%s",
                                str(xv))
                            ll_arg = astree.mk_temp_lval_expression()
                        if not (len(xv.operands) == 2):
                            chklogger.logger.warning(
                                "Expected stack offset expression in call "
                                + "ll_arg: %s",
                                str(xv))
                            ll_arg = astree.mk_integer_constant(0)
                        if not xv.operands[0].is_register_variable:
                            chklogger.logger.warning(
                                "Expected stack offset expression in call "
                                + "ll_arg: %s",
                                str(xv))
                            ll_arg = astree.mk_temp_lval_expression()
                        if not xv.operands[1].is_int_constant:
                            chklogger.logger.warning(
                                "Expected integer stack offset in call ll_arg: "
                                + "%s",
                                str(xv))
                            ll_arg = astree.mk_temp_lval_expression()
                        llregvar = cast("XprVariable", xv.operands[0])
                        llregden = cast(
                            "VRegisterVariable", llregvar.variable.denotation)
                        llreg = llregden.register
                        llreglval = astree.mk_register_variable_lval(str(llreg))
                        llregexpr = astree.mk_lval_expression(llreglval)
                        lloffset = cast("XprConstant", xv.operands[1]).intvalue
                        lloff = astree.mk_integer_constant(lloffset)
                        ll_argloc = astree.mk_binary_op("plus", llregexpr, lloff)
                        ll_arg = astree.mk_memref_expr(ll_argloc)

                    else:
                        chklogger.logger.warning(
                            "Low-level call argument %s not recognized at %s",
                            str(xv), iaddr)
                        ll_arg = astree.mk_integer_constant(0)

                    ll_args.append(ll_arg)

                    # high-level argument

                    hl_vars = [str(v) for v in x.variables()]
                    # we cannot use variable.index equality, because the
                    # var-invariant fact variable is a symbolic variable,
                    # while the argument var is a numeric variable.
                    hl_rdefs: List[Optional["ReachingDefFact"]] = [
                        rdef for rdef in rdefs
                        if rdef is not None and str(rdef.variable) in hl_vars]

                    if x.is_string_reference:
                        cstr = x.constant.string_reference()
                        saddr = hex(x.constant.value)
                        hl_arg: AST.ASTExpr = astree.mk_string_constant(
                            ll_arg, cstr, saddr)

                    elif x.is_stack_address:
                        hl_arg = XU.stack_address_to_ast_expr(
                            x, xdata, iaddr, astree)

                    elif x.is_global_address:
                        if argtype is not None and argtype.is_integer:
                            argtype = cast(AST.ASTTypInt, argtype)
                            hl_arg = astree.mk_integer_constant(
                                x.constant.value, argtype.ikind)
                        else:
                            hexgaddr = hex(x.constant.value)
                            if hexgaddr in astree.global_addresses:
                                vinfo = astree.global_addresses[hexgaddr]
                                vtype = vinfo.vtype
                                if vtype is not None:
                                    if vtype.is_array:
                                        hl_arg = astree.mk_vinfo_lval_expression(
                                            vinfo)
                                    else:
                                        hl_arg = astree.mk_address_of(
                                            astree.mk_vinfo_lval(vinfo))
                                elif (
                                        argtype is not None
                                        and (argtype.is_function
                                             or (argtype.is_pointer
                                                 and cast(
                                                     AST.ASTTypPtr,
                                                     argtype).tgttyp.is_function))):
                                    hexaddr = hex(x.constant.value)
                                    argname = "sub_" + hexaddr[2:]
                                    hl_arg = astree.mk_global_variable_expr(
                                        argname,
                                        vtype=argtype,
                                        globaladdress=x.constant.value)

                                else:
                                    chklogger.logger.warning(
                                        ("Type of global address %s at instr. "
                                         + "address %s not known"),
                                        str(x), iaddr)
                                hl_arg = astree.mk_address_of(
                                    astree.mk_vinfo_lval(vinfo))
                            else:
                                chklogger.logger.error(
                                    ("Unknown global address %s as call "
                                     + "argument at address %s"),
                                    hexgaddr, iaddr)
                                hl_arg = astree.mk_temp_lval_expression()

                    else:
                        hl_arg = XU.xxpr_to_ast_def_expr(x, xdata, iaddr, astree)

                    # add a cast if the type of the argument is not compatible
                    # with the declared parameter type
                    if argtype is not None and not hl_arg.is_ast_constant:
                        hl_arg_type = hl_arg.ctype(astree.ctyper)
                        if hl_arg_type is not None:
                            if not assign_type_compatible(
                                    astree, hl_arg_type, argtype):
                                hl_arg = astree.mk_cast_expr(argtype, hl_arg)

                    hl_args.append(hl_arg)

                    astree.add_expr_mapping(hl_arg, ll_arg)
                    astree.add_expr_reachingdefs(ll_arg, [rdef])
                    astree.add_expr_reachingdefs(hl_arg, hl_rdefs)

        ll_call = astree.mk_call(
            ll_lhs,
            ll_tgt,
            ll_args,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_call = cast(AST.ASTInstruction, astree.mk_call(
            hl_lhs,
            hl_tgt,
            hl_args,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations))

        astree.add_instr_mapping(hl_call, ll_call)
        astree.add_instr_address(hl_call, [iaddr])
        if hl_lhs is not None:
            astree.add_lval_mapping(hl_lhs, ll_lhs)
            astree.add_lval_defuses(hl_lhs, defuses[0])
            astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_call], [ll_call])
