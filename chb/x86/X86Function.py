# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs, LLC
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
"""X86 assembly function."""

import hashlib
import xml.etree.ElementTree as ET

from typing import (
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING)

from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.BDictionary import BDictionary
from chb.app.Function import Function
from chb.app.FunctionInfo import FunctionInfo
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.StringXRefs import StringsXRefs

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnInvariants import FnInvariants
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.jsoninterface.JSONResult import JSONResult

import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

from chb.x86.X86Block import X86Block
from chb.x86.X86Cfg import X86Cfg
from chb.x86.X86Dictionary import X86Dictionary
from chb.x86.X86Instruction import X86Instruction
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.models.ModelsAccess import ModelsAccess
    from chb.x86.simulation.X86SimulationState import X86SimulationState


class X86Function(Function):

    def __init__(
            self,
            path: str,
            filename: str,
            bd: BDictionary,
            ixd: InterfaceDictionary,
            finfo: FunctionInfo,
            x86d: X86Dictionary,
            stringsxrefs: StringsXRefs,
            names: Sequence[str],
            models: "ModelsAccess",
            xnode: ET.Element) -> None:
        Function.__init__(
            self, path, filename, bd, ixd, finfo, stringsxrefs, names, xnode)
        self._x86d = x86d
        self._blocks: Dict[str, X86Block] = {}
        self._cfg: Optional[X86Cfg] = None
        self._x86fnd: Optional[FunctionDictionary] = None
        self._models = models

    @property
    def x86dictionary(self) -> X86Dictionary:
        return self._x86d

    @property
    def models(self) -> "ModelsAccess":
        return self._models

    def set_fnvar_dictionary(self, xnode: ET.Element) -> FnVarDictionary:
        return FnVarDictionary(self, xnode)

    @property
    def x86functiondictionary(self) -> FunctionDictionary:
        if self._x86fnd is None:
            xfnd = self.xnode.find("instr-dictionary")
            if xfnd is None:
                raise UF.CHBError("Element instr-dictionary missing from xml")
            self._x86fnd = FunctionDictionary(self, xfnd)
        return self._x86fnd

    @property
    def blocks(self) -> Dict[str, X86Block]:
        if len(self._blocks) == 0:
            xinstrs = self.xnode.find("instructions")
            if xinstrs is None:
                raise UF.CHBError(
                    "Xml element instructions missing form function xml")
            for b in xinstrs.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Block address is missing from xml")
                self._blocks[baddr] = X86Block(self, b)
        return self._blocks

    def iter_blocks(self, f: Callable[[str, X86Block], None]) -> None:
        for (baddr, block) in sorted(self.blocks.items()):
            f(baddr, block)

    @property
    def instructions(self) -> Mapping[str, X86Instruction]:
        result: Dict[str, X86Instruction] = {}

        def f(baddr: str, block: X86Block) -> None:
            result.update(block.instructions)

        self.iter_blocks(f)
        return result

    @property
    def branchconditions(self) -> Mapping[str, X86Instruction]:
        return {}

    def strings_referenced(self) -> List[str]:
        result: List[str] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            result.extend(instr.strings_referenced)

        self.iter_instructions(f)
        return result

    @property
    def cfg(self) -> X86Cfg:
        if self._cfg is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("Element cfg missing from function xml")
            self._cfg = X86Cfg(self, xcfg)
        return self._cfg

    def iter_instructions(self, f: Callable[[str, X86Instruction], None]) -> None:
        for (ia, instr) in self.instructions.items():
            x86instr = cast(X86Instruction, instr)
            f(ia, x86instr)

    def arg_count(self) -> int:
        xvalues = self.vardictionary.constant_value_variables()
        argvalues = [x for x in xvalues if x.is_argument_value]
        argcount = 0
        for a in argvalues:
            argindex = a.argument_index()
            if argindex > argcount:
                argcount = argindex
        return argcount

    def operands(self) -> Dict[str, Sequence[X86Operand]]:
        result: Dict[str, Sequence[X86Operand]] = {}

        def f(ia: str, i: X86Instruction) -> None:
            operands = i.operands
            if len(operands) > 0:
                result[ia] = operands

        self.iter_instructions(f)
        return result

    def operand_values(self) -> Dict[str, Sequence[XXpr]]:
        result: Dict[str, Sequence[XXpr]] = {}

        def f(ia: str, i: X86Instruction) -> None:
            opvalues = i.operand_values()
            if len(opvalues) > 0:
                result[ia] = opvalues

        self.iter_instructions(f)
        return result

    def byte_string(self, chunksize: int = None) -> str:
        s: List[str] = []

        def f(ia: str, i: X86Instruction) -> None:
            s.extend(i.bytestring)

        self.iter_instructions(f)
        if chunksize is None:
            return ''.join(s)
        else:
            result = ''.join(s)
            size = len(s)
            chunks = [result[i:i+chunksize] for i in range(0, size, chunksize)]
            return '\n'.join(chunks)

    def calls_to_app_function(self, tgtaddr: str) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.is_call_to_app_function(tgtaddr):
                result.append(instr)

        self.iter_instructions(f)
        return result

    def dll_calls(self) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.is_dll_call():
                result.append(instr)

        self.iter_instructions(f)
        return result

    def branch_predicates(self) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.has_branch_predicate():
                result.append(instr)

        self.iter_instructions(f)
        return result

    def so_calls(self) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.is_so_call():
                result.append(instr)

        self.iter_instructions(f)
        return result

    def app_calls(self) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.is_app_call():
                result.append(instr)

        self.iter_instructions(f)
        return result

    def unresolved_calls(self) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.is_unresolved_call():
                result.append(instr)

        self.iter_instructions(f)
        return result

    def structured_lhs_variables(self) -> List[XVariable]:
        result: List[XVariable] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            result.extend(instr.structured_lhs())

        self.iter_instructions(f)
        return result

    def structured_lhs_instructions(self) -> List[X86Instruction]:
        result: List[X86Instruction] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            if instr.has_structured_lhs():
                result.append(instr)

        self.iter_instructions(f)
        return result

    def structured_rhs_expressions(self) -> List[XXpr]:
        result: List[XXpr] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            result.extend(instr.structured_rhs())

        self.iter_instructions(f)
        return result

    def ioc_arguments(self) -> List[Tuple[str, str, str]]:
        """Returns [ (rolename,parametername,argument value) ]."""
        result: List[Tuple[str, str, str]] = []

        def f(iaddr: str, instr: X86Instruction) -> None:
            result.extend(instr.ioc_arguments())

        self.iter_instructions(f)
        return result

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for b in sorted(self.blocks):
            block = self.blocks[b]
            result[block.baddr] = block.as_dictionary()
        return result

    def simulate_block(
            self,
            simstate: "X86SimulationState",
            blockaddr: str,
            processed: List[X86Instruction]) -> Tuple[str, List[X86Instruction]]:
        if blockaddr not in self.blocks:
            raise SU.CHBSimError(
                simstate, blockaddr, 'Block address not found: ' + str(blockaddr))
        block = self.blocks[blockaddr]

        def f(baddr: str, i: X86Instruction) -> None:
            i.simulate(simstate)
            processed.append(i)

        try:
            block.iter_instructions(f)
            return (block.baddr, processed)
        except SU.CHBSimError as e:
            e.set_instructions_processed(cast(List[Instruction], processed))
            raise
        except SU.CHBSimFallthroughException as e:
            e.set_instructions_processed(cast(List[Instruction], processed))
            e.set_block_address(block.baddr)
            raise
        except SU.CHBSimJumpException as e:
            processed.append(cast(X86Instruction, self.instruction(e.iaddr)))
            tgtaddr = str(e.tgtaddr)
            if tgtaddr in self.blocks:
                return self.simulate_block(simstate, tgtaddr, processed)
            else:
                targets = ','.join([str(t) for t in self.blocks])
                eerror = SU.CHBSimError(
                    simstate,
                    e.iaddr,
                    ('Target block address not found: '
                     + str(e.tgtaddr)
                     + ' (targets: '
                     + targets
                     + ')'))
                raise eerror

    def simulate(
            self,
            simstate: "X86SimulationState",
            processed: List[X86Instruction] = []) -> None:
        blockaddr = self.faddr
        while True:
            try:
                (baddr, processed) = self.simulate_block(
                    simstate, blockaddr, processed)
                bsuccessors = self.cfg.successors(baddr)
            except SU.CHBSimFallthroughException as e:
                baddr = e.blockaddr
                processed = cast(List[X86Instruction], e.processed)
                bsuccessors = self.cfg.successors(baddr)
                bsuccessors = [x for x in bsuccessors if not x == e.tgtaddr]

            if len(bsuccessors) == 1:
                blockaddr = bsuccessors[0]
                if not (blockaddr in self.blocks):
                    raise SU.CHBSimError(
                        simstate,
                        blockaddr,
                        'Block successor not found: ' + str(blockaddr))
            elif len(bsuccessors) == 0:
                raise SU.CHBSimError(
                    simstate,
                    blockaddr,
                    'No block successors found' + str(self.cfg))
            else:
                err = SU.CHBSimError(
                    simstate,
                    blockaddr,
                    ('Multiple block successors found: '
                     + ','.join([str(x) for x in bsuccessors])))
                err.set_instructions_processed(cast(List[Instruction], processed))
                raise err

    def to_opcode_operations_string(self) -> str:
        lines: List[str] = []
        for b in sorted(self.blocks):
            lines.append(self.blocks[b].to_opcode_operations_string())
            lines.append('-' * 80)
        return '\n'.join(lines)

    def to_string(
            self,
            bytes: bool = False,
            bytestring: bool = False,
            hash: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            sp: bool = True,
            stacklayout: bool = False) -> str:
        lines: List[str] = []
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(
                    bytes=bytes,
                    opcodewidth=opcodewidth,
                    opcodetxt=opcodetxt,
                    sp=sp))
            lines.append('-' * 80)
        if bytestring:
            lines.append(self.byte_string(chunksize=80))
        if hash:
            lines.append('hash: ' + self.md5)
        return '\n'.join(lines)

    def __str__(self) -> str:
        return self.to_string()

    def to_json_result(self) -> JSONResult:
        return JSONResult(
            "assemblyfunction", {}, "fail", "not yet implemented for x86")
