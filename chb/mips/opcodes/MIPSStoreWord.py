# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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


from typing import cast, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree

import chb.app.ASTNode as AST

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result, derefstr
from chb.mips.MIPSOperand import MIPSOperand

import chb.invariants.XXprUtil as XU

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.invariants.VAssemblyVariable import VAuxiliaryVariable
    from chb.invariants.VConstantValueVariable import VInitialRegisterValue
    from chb.invariants.XXpr import XprVariable
    from chb.mips.MIPSRegister import MIPSRegister
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("sw", MIPSOpcode)
class MIPSStoreWord(MIPSOpcode):
    """SW rt, offset(base)

    Store a word to memory.

    args[0]: index of rt in mips dictionary
    args[1]: index of offset(base) in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def global_variables(self, xdata: InstrXData) -> Mapping[str, int]:
        return xdata.xprs[0].global_variables()

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxa

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs (simplified)
        xprs[2]: address of memory location
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[0]
        rrhs = xdata.xprs[1]
        xrhs = simplify_result(xdata.args[1], xdata.args[2], rhs, rrhs)
        if lhs == '?' and len(xdata.xprs) == 3:
            lhs = derefstr(xdata.xprs[2])
        return lhs + ' := ' + xrhs

    def is_spill(self, xdata: InstrXData) -> bool:
        swaddr = xdata.xprs[2]
        if swaddr.is_stack_address:
            rhs = xdata.xprs[1]
            if rhs.is_var:
                rhsv = cast("XprVariable", rhs).variable
                if rhsv.denotation.is_auxiliary_variable:
                    v = cast("VAuxiliaryVariable", rhsv.denotation)
                    if v.auxvar.is_initial_register_value:
                        vx = cast("VInitialRegisterValue", v.auxvar)
                        r = cast("MIPSRegister", vx.register)
                        return (
                            r.is_mips_callee_saved_register
                            or r.is_mips_global_pointer
                            or r.is_mips_return_address_register)
        return False

    def ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if self.is_spill(xdata):
            return []
        else:
            rhss = XU.xxpr_to_ast_exprs(xdata.xprs[1], astree)
            lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], astree)
            if len(rhss) == 1 and len(lhss) == 1:
                rhs = rhss[0]
                lhs = lhss[0]
                assign = astree.mk_assign(lhs, rhs)
                astree.add_instruction_span(assign.id, iaddr, bytestring)
                return [assign]
            else:
                raise UF.CHBError(
                    "MIPSStoreWord: multiple expressions/lval in ast")

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   memory[base+offset] <- rt
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop)
        lhs = simstate.set(iaddr, dstop, srcval)
        simstate.increment_programcounter()
        return SU.simassign(iaddr, simstate, lhs, srcval)
