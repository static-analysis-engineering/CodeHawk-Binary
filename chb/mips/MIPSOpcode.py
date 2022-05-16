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

from typing import (
    cast, Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING)

import chb.api.MIPSLinuxSyscalls as SC

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr, XprCompound

from chb.mips.MIPSDictionaryRecord import MIPSDictionaryRecord
from chb.mips.MIPSOperand import MIPSOperand

import chb.simulation.SimUtil as SU
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


def simplify_result(id1: int, id2: int, x1: XXpr, x2: XXpr) -> str:
    if id1 == id2:
        return str(x1)
    else:
        return str(x1) + ' (= ' + str(x2) + ')'


branch_opcodes = [
    "beq", "beql", "bc1f", "bc1t",
    "bgez", "bgezl", "bgtz", "bgtzl",
    "blez", "blezl", "bltz", "bltzl",
    "bne",  "bnel"]


call_opcodes = ["jal", "jalr", "bal", "bgezal", "bltzal"]


def derefstr(x: XXpr) -> str:
    return "*(" + str(x) + ")"


def extract_string_manipulations(c1: XXpr, c2: XXpr) -> Tuple[str, str]:
    if (
            c1.is_string_manipulation_condition
            and c2.is_string_manipulation_condition):
        c1 = cast(XprCompound, c1)
        c2 = cast(XprCompound, c2)
        return (c1.string_condition_to_pretty(),
                c2.string_condition_to_pretty())
    return (str(c1), str(c2))


# groups jump table targets
def get_jump_table_targets(tgts: List[str]) -> Dict[str, List[str]]:
    result = zip(tgts[::2], tgts[1::2])
    d: Dict[str, List[str]] = {}
    for (i, j) in result:
        d.setdefault(j, [])
        d[j].append(i)
    return d


class MIPSOpcode(MIPSDictionaryRecord):

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSDictionaryRecord.__init__(self, mipsd, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        """Return lhs variables."""
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        """Return rhs expressions."""
        return xdata.xprs

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        """Return all operands from the instruction."""
        return []

    def operand_values(self, xdata: InstrXData) -> Sequence[XXpr]:
        """Return all operand values as expressions."""
        return []

    def strings(self, xdata: InstrXData) -> Sequence[str]:
        """Return strings referenced by the instruction."""
        return []

    def string_pointer_loaded(self, data: InstrXData) -> Optional[Tuple[str, str]]:
        return None

    def global_variables(self, xdata: InstrXData) -> Mapping[str, int]:
        """Return a dictionary with a count for each global variable."""
        return {}

    # returns a dictionary of name -> MIPSRegister
    def registers(self) -> Mapping[str, str]:
        result: Dict[str, str] = {}
        operands = self.operands
        for op in self.operands:
            if op.is_mips_register:
                r = op.register
                result.setdefault(str(r), r)
            elif op.is_mips_indirect_register:
                r = op.indirect_register
                result.setdefault(str(r), r)
        return result

    """
    Combines general original opcode operands from (tags,args) with generated
    (inferred) operand data from xdata to create a description of the
    instruction.
    """
    def annotation(self, xdata: InstrXData) -> str:
        return self.__str__()

    def return_value(self, xdata: InstrXData) -> Optional[XXpr]:
        raise UF.CHBError("Instruction is not a return instruction: " + str(self))

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        msg = (
            iaddr + ": "
            + bytestring
            + "  "
            + self.mnemonic
            + " "
            + self.operandstring
            + ": "
            + self.annotation(xdata))
        astree.add_instruction_unsupported(self.mnemonic, msg)
        return []

    def assembly_ast_condition(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Optional[AST.ASTExpr]:
        msg = (
            bytestring
            + "  "
            + self.mnemonic
            + " "
            + self.operandstring
            + ": "
            + self.annotation(xdata))
        raise UF.CHBError("No assembly-ast-condition defined for " + msg)

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        return self.assembly_ast(astree, iaddr, bytestring, xdata)

    def ast_condition(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Optional[AST.ASTExpr]:
        return self.assembly_ast_condition(astree, iaddr, bytestring, xdata)

    @property
    def operandstring(self) -> str:
        return ", ".join(str(op) for op in self.operands)

    @property
    def is_return_instruction(self) -> bool:
        return self.tags[0] == 'jr' and str(self.operands[0]) == 'ra'

    @property
    def is_load_word(self) -> bool:
        return self.tags[0] == 'lw'

    @property
    def is_store_word(self) -> bool:
        return self.tags[0] == 'sw'

    @property
    def is_branch_instruction(self) -> bool:
        return self.tags[0] in branch_opcodes

    @property
    def is_restore_register(self) -> bool:
        return False

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        if self.tags[0] in call_opcodes:
            return True
        elif len(xdata.tags) == 2 and xdata.tags[-1] == "call":
            return True
        else:
            return False

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        raise SU.CHBSimError(
            simstate,
            iaddr,
            ('Simulation not yet supported for '
             + str(self)
             + ' at address '
             + str(iaddr)))

    def __str__(self) -> str:
        return self.tags[0] + ':pending'
