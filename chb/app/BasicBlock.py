# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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
"""Superclass of a basic block for different architectures.

Subclasses:
 - ARMBlock
 - AsmBlock
 - MIPSBlock
"""

import hashlib
import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Mapping, Optional, Sequence, TYPE_CHECKING

from chb.app.Instruction import Instruction

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.Function


class BasicBlockFragment:
    """Represents a basic block fragment without ast control flow.

    In ARM instructions may be predicated, e.g.:

    MOVEQ R0, R1  : if condition then R0 := R1

    In the ocaml analyzer this additional control flow can be accomodated
    directly in CHIF without the need to create a separate basic block
    in the CFG (i.e. lightweight control flow). In decompilation, some of
    these instructions may be accomodated without explicit control flow (e.g.,
    by the C ternary operation), but this is not always possible.

    However, even when predicated instructions cannot be converted into
    expressions, it is not necessary to create top-level basic blocks
    that are subject to the CFG-to-AST conversion. A more light-weight
    solution is to embed the necessary control flow (notably limited
    to branches and instruction sequences) within the block created for
    the original basic block.

    The basic block is partitioned into a linear sequence of BasicBlock
    Fragments, where each fragment can be one of the following:
    - a (linear) instruction sequence statement
    - a branch statement containing a condition and a single (if) branch
    - a branch statement containing a condition and a then and an else
       branch.
    In case of the branch statement either branch can have one or more
    instructions that have the same condition setter and the same
    condition.
    """

    def __init__(self, instr: Instruction) -> None:
        self._linear: List[Instruction] = []
        self._thenbranch: List[Instruction] = []
        self._elsebranch: List[Instruction] = []
        self._setter: Optional[str] = None
        self._condition: Optional[str] = None
        self.add_instr(instr)

    @property
    def condition(self) -> Optional[str]:
        return self._condition

    @property
    def setter(self) -> Optional[str]:
        return self._setter

    @property
    def is_predicated(self) -> bool:
        return self.condition is not None

    @property
    def is_then_only(self) -> bool:
        return self.is_predicated and len(self.elsebranch) == 0

    @property
    def linear(self) -> List[Instruction]:
        return self._linear

    @property
    def thenbranch(self) -> List[Instruction]:
        return self._thenbranch

    @property
    def elsebranch(self) -> List[Instruction]:
        return self._elsebranch

    @property
    def is_empty(self) -> bool:
        return (
            len(self.linear) + len(self.thenbranch) + len(self.elsebranch) == 0)

    def add_predicated_instr(self, instr: Instruction) -> None:
        if self.is_empty:
            self._condition = instr.get_instruction_cc()
            self._setter = instr.get_instruction_condition_setter()
            self.thenbranch.append(instr)
        elif self.is_predicated:
            if self.condition == instr.get_instruction_cc():
                self.thenbranch.append(instr)
            else:
                self.elsebranch.append(instr)
        else:
            raise UF.CHBError("Cannot add predicated instruction to linear frag")

    def add_linear_instr(self, instr: Instruction) -> None:
        if self.is_empty or (not self.is_predicated):
            self.linear.append(instr)
        else:
            raise UF.CHBError(
                "Cannot add unpredicated instruction to predicate fragment")

    def add_instr(self, instr: Instruction) -> None:
        if instr.has_control_flow():
            self.add_predicated_instr(instr)
        else:
            self.add_linear_instr(instr)

    def __str__(self) -> str:
        lines: List[str] = []
        if self.condition:
            setter = " (" + self.setter + ")" if self.setter else ""
            lines.append("condition: " + self.condition + setter)
        if self.linear:
            lines.append("linear")
            for i in self.linear:
                lines.append("  " + str(i))
        if self.thenbranch:
            lines.append("then:")
            for i in self.thenbranch:
                lines.append("  " + str(i))
        if self.elsebranch:
            lines.append("else:")
            for i in self.elsebranch:
                lines.append("  " + str(i))
        return "\n".join(lines)


class BasicBlock(ABC):

    def __init__(
            self,
            xnode: ET.Element) -> None:
        self.xnode = xnode
        self._partition: Dict[str, BasicBlockFragment] = {}

    @property
    def partition(self) -> Dict[str, BasicBlockFragment]:
        return self._partition

    @property
    def baddr(self) -> str:
        _baddr = self.xnode.get("ba")
        if _baddr is None:
            raise UF.CHBError("Basic block address is missing from xml")
        return _baddr

    @property
    def real_baddr(self) -> str:
        _baddr = self.baddr
        if _baddr.startswith("F"):
            return _baddr.split("_")[-1]
        else:
            return _baddr

    @property
    def lastaddr(self) -> str:
        return sorted(self.instructions.keys())[-1]

    @property
    def real_lastaddr(self) -> str:
        _addr = self.lastaddr
        if _addr.startswith("F"):
            return _addr.split("_")[-1]
        else:
            return _addr

    @property
    def last_instruction(self) -> Instruction:
        lastaddr = sorted(self.instructions.keys())[-1]
        return self.instructions[lastaddr]

    @property
    def has_return(self) -> bool:
        return self.last_instruction.is_return_instruction

    @property
    def has_conditional_return(self) -> bool:
        return self.last_instruction.is_conditional_return_instruction

    def has_control_flow(self) -> bool:
        """Returns true if this block contains predicated instructions that
        are not otherwise covered in aggregates or by other conditions.

        The case of a block with a conditional return is already handled in
        the Cfg, so it is excluded here.

        The case of a block with a conditional return and other conditional
        instructions is not yet handled.
        """

        count = len([i for i in self.instructions.values() if i.has_control_flow()])
        if count == 1 and self.has_conditional_return:
            return False

        return any(i.has_control_flow() for i in self.instructions.values())

    def partition_control_flow(self) -> None:
        curblock: Optional[BasicBlockFragment] = None
        curaddr: Optional[str] = None

        for (a, i) in sorted(self.instructions.items()):
            if curaddr is None or curblock is None:
                curaddr = a
                curblock = BasicBlockFragment(i)
            else:
                if i.has_control_flow():
                    if curblock.is_predicated:
                        if i.get_instruction_condition_setter() == curblock.setter:
                            curblock.add_instr(i)
                        else:
                            self._partition[curaddr] = curblock
                            curblock = BasicBlockFragment(i)
                            curaddr = a
                    else:
                        self._partition[curaddr] = curblock
                        curblock = BasicBlockFragment(i)
                        curaddr = a
                else:
                    if curblock.is_predicated:
                        self._partition[curaddr] = curblock
                        curblock = BasicBlockFragment(i)
                        curaddr = a
                    else:
                        curblock.add_instr(i)

        if curaddr is not None and curblock is not None:
            self._partition[curaddr] = curblock

    @property
    @abstractmethod
    def instructions(self) -> Mapping[str, Instruction]:
        ...

    @property
    def call_instructions(self) -> Sequence[Instruction]:
        result: List[Instruction] = []
        for (ia, instr) in sorted(self.instructions.items()):
            if instr.is_call_instruction:
                result.append(instr)
        return result

    @property
    def jump_instructions(self) -> Sequence[Instruction]:
        result: List[Instruction] = []
        for (ia, instr) in sorted(self.instructions.items()):
            if instr.is_jump_instruction:
                result.append(instr)
        return result

    @property
    def store_instructions(self) -> Sequence[Instruction]:
        result: List[Instruction] = []
        for (ia, instr) in sorted(self.instructions.items()):
            if instr.is_store_instruction:
                result.append(instr)
        return result

    @property
    def load_instructions(self) -> Sequence[Instruction]:
        result: List[Instruction] = []
        for (ia, instr) in sorted(self.instructions.items()):
            if instr.is_load_instruction:
                result.append(instr)
        return result

    def has_instruction(self, iaddr: str) -> bool:
        return iaddr in self.instructions

    def instruction(self, iaddr: str) -> Instruction:
        if iaddr in self.instructions:
            return self.instructions[iaddr]
        raise UF.CHBError("Instruction " + iaddr + " not found")

    def md5(self) -> str:
        m = hashlib.md5()
        for instr in self.instructions.values():
            m.update(instr.bytestring.encode("utf-8"))
        return m.hexdigest()

    def rev_md5(self) -> str:
        """Use reverse bytestring to account for difference in endianness."""

        m = hashlib.md5()
        for instr in self.instructions.values():
            m.update(instr.rev_bytestring.encode("utf-8"))
        return m.hexdigest()

    @abstractmethod
    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            typingrules: bool = False,
            sp: bool = True) -> str:
        ...

    def to_json_result(self) -> JSONResult:
        raise NotImplementedError("BasicBlock.to_json_result")

    def __str__(self) -> str:
        return self.to_string()
