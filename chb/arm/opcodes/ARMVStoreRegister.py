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

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("VSTR", ARMOpcode)
class ARMVStoreRegister(ARMOpcode):
    """Stores a single extension register to memory

    VSTR<c> <Dd>, [<Rn>{, #+/-<imm>}]
    VSTR<c> <Sd>, [<Rn>{, #+/-<imm>}]

    tags[1]: <c>
    args[0]: index of Dd/Sd in armdictionary
    args[1]: index of Rn in armdictionary
    args[2]: index of memory location in armdictionary

    xdata format: a:vxxxrrdh
    ------------------------
    vars[0]: lhs (vmem)
    xprs[0]: expression to be stored
    xprs[1]: expression to be stored rewritten
    xprs[2]: base register expression
    xprs[3]: base register expression rewritten
    xprs[4]: address expression
    rdefs[0]: reaching def of src expression
    rdefs[1]: reaching def of base expression
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VStore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2]]

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        assignment = lhs + " := " + rhs
        if xdata.has_unknown_instruction_condition():
            return "if ? then " + assignment
        elif xdata.has_instruction_condition():
            c = str(xdata.xprs[1])
            return "if " + c + " then " + assignment
        else:
            return assignment

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VSTR"]

        (ll_rhs, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_lhs, ll_preinstrs, ll_postinstrs) = self.opargs[2].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        xaddr = xdata.xprs[2]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_preinstrs: List[AST.ASTInstruction] = []
        hl_postinstrs: List[AST.ASTInstruction] = []

        rhsexprs = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)

        if len(rhsexprs) == 0:
            raise UF.CHBError(
                "VStoreRegister (VSTR): no rhs found")

        if len(rhsexprs) > 1:
            raise UF.CHBError(
                "VStoreRegister (VSTR): multiple rhs values: "
                + ", ".join(str(x) for x in rhsexprs))

        hl_rhs = rhsexprs[0]
        hl_rhs_type = hl_rhs.ctype(astree.ctyper)

        if lhs.is_tmp or lhs.has_unknown_memory_base():
            hl_lhs = XU.xmemory_dereference_lval(xaddr, xdata, iaddr, astree)
            astree.add_lval_store(hl_lhs)

        else:
            lvals = XU.xvariable_to_ast_lvals(lhs, xdata, astree, ctype=hl_rhs_type)
            if len(lvals) == 0:
                raise UF.CHBError(
                    "VStoreRegister (VSTR): no lhs found")

            if len(lvals) > 1:
                raise UF.CHBError(
                    "VStoreRegister (VSTR): multiple lhs values found: "
                    + ", ".join(str(v) for v in lvals))

            hl_lhs = lvals[0]
            astree.add_lval_store(hl_lhs)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[1]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if ll_lhs.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, ll_lhs.lhost).memexp
            astree.add_expr_reachingdefs(memexp, [rdefs[0]])

        return ([hl_assign], (ll_preinstrs + [ll_assign] + ll_postinstrs))
