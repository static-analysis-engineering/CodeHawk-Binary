# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs, LLC
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
"""X86 Assembly Instruction Data."""

import xml.etree.ElementTree as ET

from typing import cast, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget, StubTarget
from chb.api.FunctionStub import DllFunction

from chb.app.BDictionary import AsmAddress
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData

from chb.app.StackPointerOffset import StackPointerOffset

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

from chb.x86.X86DictionaryRecord import X86DictionaryRecord
from chb.x86.X86Opcode import X86Opcode
from chb.x86.opcodes.X86Call import X86Call
from chb.x86.opcodes.X86IndirectJmp import X86IndirectJmp
from chb.x86.X86Operand import X86Operand

from chb.x86.simulation.X86SimulationState import X86SimulationState

if TYPE_CHECKING:
    from chb.x86.X86Block import X86Block
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.X86Function import X86Function


class X86Instruction(Instruction):

    def __init__(self,
                 x86block: "X86Block",
                 xnode: ET.Element) -> None:
        Instruction.__init__(self, xnode)
        self._x86block = x86block
        self._opcode: Optional[X86Opcode] = None
        self._opcodetext: Optional[str] = None
        self._xdata: Optional[InstrXData] = None

    @property
    def x86block(self) -> "X86Block":
        return self._x86block

    @property
    def x86dictionary(self) -> "X86Dictionary":
        return self.x86block.x86dictionary

    @property
    def x86functiondictionary(self) -> "FunctionDictionary":
        return self.x86block.x86functiondictionary

    @property
    def x86function(self) -> "X86Function":
        return self.x86block.x86function

    @property
    def opcode(self) -> X86Opcode:
        if self._opcode is None:
            self._opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        return self._opcode

    @property
    def xdata(self) -> InstrXData:
        if self._xdata is None:
            self._xdata = self.x86functiondictionary.read_xml_instrx(self.xnode)
        return self._xdata

    @property
    def mnemonic(self) -> str:
        return self.opcode.mnemonic

    @property
    def opcodetext(self) -> str:
        if self._opcodetext is None:
            self._opcodetext = self.x86dictionary.read_xml_opcode_text(self.xnode)
        return self._opcodetext

    @property
    def operands(self) -> Sequence[X86Operand]:
        return self.opcode.operands

    @property
    def bytestring(self) -> str:
        return self.x86dictionary.read_xml_bytestring(self.xnode)

    @property
    def stackpointer_offset(self) -> StackPointerOffset:
        return self.x86functiondictionary.read_xml_sp_offset(self.xnode)

    @property
    def is_return_instruction(self) -> bool:
        return self.opcode.is_return

    @property
    def is_conditional_branch_instruction(self) -> bool:
        return self.opcode.is_conditional_branch

    @property
    def is_branch_instruction(self) -> bool:
        return self.is_conditional_branch_instruction

    def has_branch_predicate(self) -> bool:
        if self.opcode.is_conditional_branch:
            return self.opcode.has_predicate(self.xdata)
        else:
            return False

    @property
    def strings_referenced(self) -> List[str]:
        return []

    def branch_predicate(self) -> XXpr:
        if self.has_branch_predicate():
            return self.opcode.predicate(self.xdata)
        else:
            raise UF.CHBError("Instruction does not have a branch predicate: "
                              + str(self))

    def ft_conditions(self) -> List[XXpr]:
        if self.has_branch_condition():
            return self.opcode.ft_conditions(self.xdata)
        else:
            return []

    def is_indirect_jump(self) -> bool:
        return self.opcode.is_indirect_jump

    def jumptable_targets(self) -> List[str]:
        if self.is_indirect_jump():
            opc = cast(X86IndirectJmp, self.opcode)
            return opc.targets(self.xdata)
        else:
            raise UF.CHBError("Instruction is not an indirect jump: " + str(self))

    def selector_expr(self) -> XXpr:
        if self.is_indirect_jump():
            return self.opcode.selector_expr(self.xdata)
        else:
            raise UF.CHBError("Instruction is not an indirect jump: " + str(self))

    def has_branch_condition(self) -> bool:
        if self.is_conditional_branch_instruction:
            return len(self.xdata.xprs) > 0
        return False

    def branch_condition(self) -> XXpr:
        if self.has_branch_condition():
            return self.xdata.xprs[0]
        else:
            raise UF.CHBError('Instruction does not have a branch condition: '
                              + str(self))

    def has_return_expr(self) -> bool:
        return self.opcode.has_return_expr()

    def return_expr(self) -> XXpr:
        return self.opcode.return_expr(self.xdata)

    @property
    def annotation(self) -> str:
        opcode = self.opcode.annotation(self.xdata)
        return str(opcode).ljust(40)

    def opcode_operations(self) -> Sequence[str]:
        return self.opcode.opcode_operations()

    def operand_values(self) -> Sequence[XXpr]:
        return self.opcode.operand_values(self.xdata)

    def is_function_argument(self) -> bool:
        return self.xdata.is_function_argument

    def function_argument_callsite(self) -> AsmAddress:
        return self.xdata.function_argument_callsite

    @property
    def is_call_instruction(self) -> bool:
        return self.opcode.is_call

    def call_target(self) -> CallTarget:
        if self.opcode.is_call:
            opc = cast(X86Call, self.opcode)
            return opc.call_target(self.xdata)
        else:
            raise UF.CHBError("Instruction is not a call instruction")

    def call_arguments(self) -> List[XXpr]:
        if self.opcode.is_call:
            opc = cast(X86Call, self.opcode)
            return opc.arguments(self.xdata)
        else:
            raise UF.CHBError("Instruction is not a call instruction")

    # returns a list of (rolename,parameter name, argument value)
    def ioc_arguments(self) -> List[Tuple[str, str, str]]:
        results: List[Tuple[str, str, str]] = []
        if self.is_dll_call():
            models = self.x86function.models
            tgt = cast(DllFunction, cast(StubTarget, self.call_target()).stub)
            args = self.call_arguments()
            dll = tgt.dll
            fname = tgt.name
            if models.has_dll_function_summary(dll, fname):
                summary = models.dll_function_summary(dll, fname)
                params = summary.signature.parameters
                if len(args) == len(params):
                    for (param, arg) in zip(params, args):
                        iocroles = [role for role in param.roles() if role.is_ioc]
                        for iocrole in iocroles:
                            ioc = iocrole.ioc_name
                            rolename = iocrole.role_name
                            results.append((rolename, param.name, str(arg)))
        return results

    def annotated_call_arguments(self) -> List[Tuple[str, str]]:
        if self.opcode.is_call:
            opc = cast(X86Call, self.opcode)
            return opc.annotated_arguments(self.xdata)
        return []

    def is_call_to_app_function(self, tgtaddr: str) -> bool:
        if self.opcode.is_call:
            opc = cast(X86Call, self.opcode)
            return (
                opc.is_app_call(self.xdata)
                and str(opc.app_target(self.xdata)) == tgtaddr)
        else:
            return False

    def is_dll_call(self) -> bool:
        return self.opcode.is_dll_call(self.xdata)

    def is_so_call(self) -> bool:
        return self.opcode.is_so_call(self.xdata)

    def is_app_call(self) -> bool:
        return self.opcode.is_app_call(self.xdata)

    def is_unresolved_call(self) -> bool:
        return self.opcode.is_unresolved_call(self.xdata)

    def has_global_value_unresolved_call_target(self) -> bool:
        if self.opcode.is_call:
            opc = cast(X86Call, self.opcode)
            return opc.has_global_value_unresolved_call_target(self.xdata)
        else:
            return False

    def unresolved_call_target_expr(self) -> XXpr:
        if self.has_global_value_unresolved_call_target():
            opc = cast(X86Call, self.opcode)
            return opc.unresolved_call_target_expr(self.xdata)
        else:
            raise UF.CHBError("Instruction is not an unresolved call")

    def structured_lhs(self) -> List[XVariable]:
        lhs = self.opcode.lhs(self.xdata)
        return [x for x in lhs if x.is_structured_var]

    def has_structured_lhs(self) -> bool:
        return len(self.structured_lhs()) > 0

    def rhs(self) -> List[XXpr]:
        return self.opcode.rhs(self.xdata)

    def structured_rhs(self) -> List[XXpr]:
        rhs = self.rhs()
        return [x for x in rhs if x.is_structured_expr]

    def is_memory_assign(self) -> bool:
        if self.mnemonic == 'mov':
            xdata = self.xdata
            if len(xdata.vars) == 1:
                lhs = xdata.vars[0]
                return (lhs.has_denotation()
                        and lhs.denotation.is_memory_variable)
        return False

    def memory_assign(self) -> Tuple[XVariable, XXpr]:
        if self.is_memory_assign():
            xdata = self.xdata
            lhs = xdata.vars[0]
            rhs = xdata.xprs[1]
            return (lhs, rhs)
        else:
            raise UF.CHBError('Instruction is not a memory assign')

    def simulate(self, simstate: "X86SimulationState") -> None:
        try:
            self.opcode.simulate(self.iaddr, simstate)
        except SU.CHBSimError as e:
            e.instrtxt = self.to_string()
            raise e

    def to_opcode_operations_string(self, opcodewidth: int = 25) -> str:
        popcode = self.opcodetext.ljust(opcodewidth)
        opcodeops = '; '.join(self.opcode_operations())
        return popcode + opcodeops

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            sp: bool = True) -> str:
        pesp = str(self.stackpointer_offset) + '  ' if sp else ''
        pbytes = self.bytestring.ljust(20) if bytes else ''
        popcode = self.opcodetext.ljust(opcodewidth) if opcodetxt else ''
        return pesp + pbytes + popcode + self.annotation

    def __str__(self) -> str:
        return self.to_string()
