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

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VAssemblyVariable import VMemoryVariable


@armregistry.register_tag("STRB", ARMOpcode)
class ARMStoreRegisterByte(ARMOpcode):
    """Stores the least significant byte from a register into memory.

    STRB<c> <Rt>, [<base>, <offset>]

    tags[1]: <c>
    args[0]: index of source operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of index in armdictionary
    args[3]: index of memory location in armdictionary
    args[4]: is-wide (thumb)

    xdata format: a:vxxxxrrrdh
    --------------------------
    vars[0]: lhs
    xprs[0]: xrn (base register)
    xprs[1]: xrm (index)
    xprs[2]: xrt (rhs, source register)
    xprs[3]: xrt (rhs, simplified)
    xprs[4]: xaddr (memory address)
    xprs[5]: condition (if TC is set)
    rdefs[0]: rn
    rdefs[1]: rm
    rdefs[2]: rt
    uses[0]: lhs
    useshigh[0]: lhs

    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "StoreRegisterByte")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2, 3]]

    @property
    def membase_operand(self) -> ARMOperand:
        return self.opargs[1]

    @property
    def memindex_operand(self) -> ARMOperand:
        return self.opargs[2]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[3])
        assign = lhs + " := " + rhs

        xctr = 5
        if xdata.has_instruction_condition():
            pcond = "if " + str(xdata.xprs[xctr]) + " then "
            xctr += 1
        elif xdata.has_unknown_instruction_condition():
            pcond = "if ? then "
        else:
            pcond = ""

        return pcond + assign

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "STRB"]

        (ll_rhs, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_lhs, ll_preinstrs, ll_postinstrs) = self.opargs[3].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_preinstrs: List[AST.ASTInstruction] = []
        hl_postinstrs: List[AST.ASTInstruction] = []

        if rhs.is_register_variable:
            rhsexprs = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        else:
            rhsexprs = XU.xxpr_to_ast_exprs(rhs, xdata, astree)

        if len(rhsexprs) == 0:
            raise UF.CHBError("No rhs for StoreRegisterByte (STRB) at " + iaddr)

        if len(rhsexprs) > 1:
            raise UF.CHBError(
                "Multiple rhs values for StoreRegisterByte (STRB) at "
                + iaddr
                + ": "
                + ", ".join(str(x) for x in rhsexprs))

        hl_rhs = rhsexprs[0]

        lvals = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lvals) == 0:
            raise UF.CHBError(
                "No lhs value for StoreRegisterByte (STRB) at " + iaddr)

        if len(lvals) > 1:
            raise UF.CHBError(
                "Multiple lhs values for StoreRegisterByte (STRB) at "
                + iaddr
                + ": "
                + ", ".join(str(x) for x in lvals))

        hl_lhs = lvals[0]

        if lhs.is_tmp or lhs.has_unknown_memory_base():
            hl_mem_lhs = None
            address = xdata.xprs[4]
            astaddrs = XU.xxpr_to_ast_def_exprs(address, xdata, iaddr, astree)
            if len(astaddrs) == 1:
                astaddr = astaddrs[0]
                if astaddr.is_ast_addressof:
                    hl_mem_lhs = cast(AST.ASTAddressOf, astaddr).lval
                else:
                    astaddrtype = astaddr.ctype(astree.ctyper)
                    if astaddrtype is not None:
                        if astaddrtype.is_pointer:
                            astaddrtype = cast(AST.ASTTypPtr, astaddrtype)
                            astaddrtgttype = astaddrtype.tgttyp
                            if astree.type_size_in_bytes(astaddrtgttype) == 1:
                                if astaddr.is_ast_binary_op:
                                    (base, offsets) = astree.split_address_int_offset(astaddr)
                                    if base.is_ast_lval_expr:
                                        base = cast(AST.ASTLvalExpr, base)
                                        newoffset = astree.add_index_list_offset(
                                            base.lval.offset, offsets)
                                        hl_mem_lhs = astree.mk_lval(base.lval.lhost, newoffset)
            if hl_mem_lhs is None:
                hl_lhs = XU.xmemory_dereference_lval(xdata.xprs[4], xdata, iaddr, astree)
            else:
                hl_lhs = hl_mem_lhs
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
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[2]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if ll_lhs.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, ll_lhs.lhost).memexp
            astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        return ([hl_assign], [ll_assign])
