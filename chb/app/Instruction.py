# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
"""Abstract superclass of an assembly instruction in different architectures.

Subclasses:
 - ARMInstruction
 - AsmInstruction
 - MIPSInstruction
"""

import hashlib
import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod

from typing import Callable, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.FunctionDictionary import FunctionDictionary

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.InvariantFact import InvariantFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.InstrXData import InstrXData
    from chb.app.MemoryAccess import MemoryAccess
    from chb.app.Operand import Operand
    from chb.app.StackPointerOffset import StackPointerOffset
    from chb.bctypes.BCTyp import BCTyp
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class Instruction(ABC):

    def __init__(
            self,
            xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def iaddr(self) -> str:
        _iaddr = self.xnode.get("ia")
        if _iaddr is None:
            raise UF.CHBError("Instruction address is missing from xml")
        return _iaddr

    @property
    def real_iaddr(self) -> str:
        _iaddr = self.iaddr
        if _iaddr.startswith("F"):
            return _iaddr.split("_")[-1]
        else:
            return _iaddr

    @property
    @abstractmethod
    def mnemonic(self) -> str:
        ...

    @property
    def mnemonic_stem(self) -> str:
        """Return the core part of the mnemonic without extensions."""

        return self.mnemonic

    @property
    @abstractmethod
    def opcodetext(self) -> str:
        ...

    @property
    @abstractmethod
    def operands(self) -> Sequence["Operand"]:
        ...

    @property
    def operandstring(self) -> str:
        return ", ".join(str(p) for p in self.operands)

    @property
    @abstractmethod
    def annotation(self) -> str:
        ...

    @property
    @abstractmethod
    def xdata(self) -> "InstrXData":
        ...

    @property
    @abstractmethod
    def stackpointer_offset(self) -> "StackPointerOffset":
        ...

    @property
    @abstractmethod
    def bytestring(self) -> str:
        ...

    @property
    def size(self) -> int:
        """Returns the size of the instruction in bytes."""

        return len(self.bytestring) // 2

    @property
    def rev_bytestring(self) -> str:
        """Reverse byte string to account for different endianness."""

        b = self.bytestring
        revb = "".join(i+j for i, j in zip(b[:-1][::-2], b[::-2]))
        return revb

    def md5(self) -> str:
        m = hashlib.md5()
        m.update(self.bytestring.encode("utf-8"))
        return m.hexdigest()

    def rev_md5(self) -> str:
        """Use reverse byte string to account for difference in endianness."""

        m = hashlib.md5()
        m.update(self.rev_bytestring.encode("utf-8"))
        return m.hexdigest()

    @property
    @abstractmethod
    def invariants(self) -> Sequence[InvariantFact]:
        ...

    @property
    @abstractmethod
    def strings_referenced(self) -> Sequence[str]:
        ...

    @property
    @abstractmethod
    def lhs(self) -> Sequence[XVariable]:
        """Return all left-hand-side variables that get assigned."""
        ...

    @property
    @abstractmethod
    def rhs(self) -> Sequence[XXpr]:
        """Return all rhs expressions that get assigned."""
        ...

    @property
    @abstractmethod
    def is_call_instruction(self) -> bool:
        ...

    @property
    @abstractmethod
    def is_jump_instruction(self) -> bool:
        ...

    @property
    @abstractmethod
    def is_load_instruction(self) -> bool:
        """Return true if this instruction loads data from memory."""
        ...

    @property
    @abstractmethod
    def is_store_instruction(self) -> bool:
        """Return true if this instruction stores data to memory."""
        ...

    @property
    @abstractmethod
    def is_return_instruction(self) -> bool:
        ...

    @property
    def is_nop_instruction(self) -> bool:
        return False

    @property
    @abstractmethod
    def call_target(self) -> CallTarget:
        ...

    @property
    @abstractmethod
    def call_arguments(self) -> Sequence["XXpr"]:
        ...

    @property
    def memory_accesses(self) -> Sequence["MemoryAccess"]:
        return []

    @property
    @abstractmethod
    def is_branch_instruction(self) -> bool:
        ...

    @property
    def jump_target(self) -> Optional["XXpr"]:
        return None

    @property
    def is_unresolved(self) -> bool:
        """Return true if something about this instruction is unresolved."""

        return False

    @property
    def is_subsumed(self) -> bool:
        """Return true if another instruction incorporates this instruction."""

        return False

    def subsumed_by(self) -> str:
        """Return the address of the instruction that subsumes this instruction."""

        raise UF.CHBError("Instruction is not subsumed.")

    @property
    @abstractmethod
    def ft_conditions(self) -> Sequence[XXpr]:
        ...

    @abstractmethod
    def string_pointer_loaded(self) -> Optional[Tuple[str, str]]:
        """Return string loaded and destination operand for pointer, or None."""
        ...

    @abstractmethod
    def global_refs(self) -> Tuple[Sequence["XVariable"], Sequence["XXpr"]]:
        """Return a pair of lhs, rhs global references."""
        ...

    def lhs_variables(
            self, filter: Callable[[XVariable], bool]) -> List[XVariable]:
        return []

    def rhs_expressions(self, filter: Callable[[XXpr], bool]) -> List[XXpr]:
        return []

    def return_value(self) -> Optional[XXpr]:
        return None

    def assembly_ast(self, astree: ASTInterface) -> List[AST.ASTInstruction]:
        raise UF.CHBError("assembly-ast not defined")

    def ast(self, astree: ASTInterface) -> List[AST.ASTInstruction]:
        raise UF.CHBError("ast (abstract-syntax-tree) not defined")

    def ast_prov(self, astree: ASTInterface) -> Tuple[
            List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError("ast-prov not defined")

    def is_condition_true(self) -> bool:
        return False

    def ast_condition_prov(self, astree: ASTInterface, reverse: bool = False) -> Tuple[
            Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:
        raise UF.CHBError("ast-condition-prov not defined")

    def assembly_ast_condition(
            self,
            astree: ASTInterface,
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        raise UF.CHBError("assembly-ast-condition not defined")

    def ast_case_expression(
            self, target: str, astree: ASTInterface) -> Optional[AST.ASTExpr]:
        return None

    def ast_switch_condition_prov(
            self, astree: ASTInterface) -> Tuple[
            Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:
        raise UF.CHBError("ast-switch-condition-prov not defined")

    def rdef_locations(self) -> Dict[str, List[List[str]]]:
        """Returns for each register, which locations must be combined."""

        return {}

    def lhs_types(self) -> Dict[str, "BCTyp"]:
        """Returns a mapping from lhs assigned to its type."""

        return {}

    @abstractmethod
    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            sp: bool = True) -> str:
        ...

    def to_json_result(self) -> JSONResult:
        raise NotImplementedError("Instruction.to_json_result")

    def __str__(self) -> str:
        return self.to_string()

