# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2024  Aarno Labs LLC
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
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr, XprCompound
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.bctypes.BCTyp import BCTypFun
    from chb.invariants.VarInvariantFact import ReachingDefFact
    from chb.invariants.VAssemblyVariable import VRegisterVariable
    from chb.invariants.VConstantValueVariable import VFunctionReturnValue
    from chb.invariants.XXpr import XprConstant, XprVariable


class ARMCallOpcode(ARMOpcode):
    """Generic call functionality, covers BL and BLX.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary

    xdata format: a:x[2n]xr[n]dh, call   (n arguments)
    -------------------------------------------------
    xprs[0..2n-1]: (arg location expr, arg value expr) * n
    xprs[2n]: call target expression
    rdefs[0..n-1]: arg location reaching definitions
    uses[0]: lhs
    useshigh[0]: lhs

    or (if call target is not known):
    xdata format: a:xxxxx
    ---------------------
    vars[0]: return value variable
    xprs[0..3]: expressions for R0-R3
    xprs[4]: target expression
    rdefs[0]: target reaching definition
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def argument_count(self, xdata: InstrXData) -> int:
        if self.is_call_instruction(xdata):
            argcount = xdata.call_target_argument_count()
            if argcount is not None:
                return argcount
        chklogger.logger.warning(
            "Call instruction does not have argument count")
        return 0

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in self.arguments(xdata)]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs[:self.argument_count(xdata)]

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) >= 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def annotation(self, xdata: InstrXData) -> str:
        if self.is_call(xdata) and xdata.has_call_target():
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"

        ctgt = str(xdata.xprs[0])
        return "call " + ctgt

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

        annotations: List[str] = [iaddr, "BL"]

        # low-level call data

        lhs = xdata.vars[0]
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

        # argument data

        xprs = xdata.xprs
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        argcount = self.argument_count(xdata)

        ll_args: List[AST.ASTExpr] = []
        hl_args: List[AST.ASTExpr] = []

        if argcount > 0:
            xargs = xdata.xprs[:argcount]
            xvarargs = xdata.xprs[argcount:(2 * argcount)]
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
                for (x, xv, rdef) in zip(xargs, xvarargs, llrdefs):

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
                            ll_arg = astree.mk_integer_constant(0)
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
                            ll_arg = astree.mk_integer_constant(0)
                        if not xv.operands[1].is_int_constant:
                            chklogger.logger.warning(
                                "Expected integer stack offset in call ll_arg: "
                                + "%s",
                                str(xv))
                            ll_arg = astree.mk_integer_constant(0)
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
                        negoffset = x.stack_address_offset()
                        offset = -negoffset
                        stackvar = astree.mk_stack_variable_lval(offset)
                        hl_arg = astree.mk_lval_expr(stackvar)

                    else:
                        hl_arg = XU.xxpr_to_ast_def_expr(x, xdata, iaddr, astree)
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

        # high-level call data

        hl_tgt = ll_tgt
        hl_lhs: Optional[AST.ASTLval] = None

        # construct high-level target
        finfo = xdata.function.finfo
        if finfo.has_call_target_info(iaddr):
            ctinfo = finfo.call_target_info(iaddr)
            fname = ctinfo.target_interface.name
            ftype = ctinfo.target_interface.bctype
            astftype: Optional[AST.ASTTyp] = None
            if ftype is not None:
                astftype = ftype.convert(astree.typconverter)
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
                    fname, globaladdress=gaddr, vtype=astftype)

            if ftype is not None and ftype.is_function:
                ftype = cast("BCTypFun", ftype)
                rtype = ftype.returntype
            else:
                rtype = ctinfo.target_interface.signature.returntype
            asttype = rtype.convert(astree.typconverter)
            if not rtype.is_void:
                hl_lhs = XU.xvariable_to_ast_lval(
                    lhs, xdata, iaddr, astree, ctype=asttype)

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
