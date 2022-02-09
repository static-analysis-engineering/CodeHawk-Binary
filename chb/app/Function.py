# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
"""Abstract superclass for different types of assembly functions.

Subclasses:
   arm/ARMFunction
   mips/MIPSFunction
   x86/X86Function

"""

import hashlib
import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod
from typing import (
    Any, Callable, cast, Dict, List, Mapping, NewType, Optional, Sequence, Tuple, Union)

from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree, VariableNamesRec
from chb.app.ASTNode import ASTNode
from chb.app.BasicBlock import BasicBlock
from chb.app.BDictionary import BDictionary
from chb.app.Cfg import Cfg
from chb.app.FunctionInfo import FunctionInfo
from chb.app.Instruction import Instruction
from chb.app.StringXRefs import StringsXRefs

from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnXprDictionary import FnXprDictionary
from chb.invariants.InvariantFact import InvariantFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.userdata.UserHints import UserHints

import chb.util.fileutil as UF


class Function(ABC):

    def __init__(
            self,
            path: str,
            filename: str,
            bd: BDictionary,
            ixd: InterfaceDictionary,
            finfo: FunctionInfo,
            stringsxrefs: StringsXRefs,
            names: Sequence[str],
            xnode: ET.Element) -> None:
        self.xnode = xnode
        self._path = path
        self._filename = filename
        self._bd = bd
        self._ixd = ixd
        self._finfo = finfo
        self._stringsxrefs = stringsxrefs
        self._names = names
        self._vd: Optional[FnVarDictionary] = None
        self._id: Optional[FnInvDictionary] = None
        self._invariants: Dict[str, List[InvariantFact]] = {}

    @property
    def path(self) -> str:
        return self._path

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def bd(self) -> BDictionary:
        return self._bd

    @property
    def ixd(self) -> InterfaceDictionary:
        return self._ixd

    @property
    def finfo(self) -> FunctionInfo:
        return self._finfo

    @property
    def stringsxrefs(self) -> StringsXRefs:
        return self._stringsxrefs

    @property
    def names(self) -> Sequence[str]:
        return self._names

    @property
    def faddr(self) -> str:
        faddr = self.xnode.get("a")
        if faddr is None:
            raise UF.CHBError("Assembly function address is missing from xml")
        return faddr

    @abstractmethod
    def set_fnvar_dictionary(self, xnode: ET.Element) -> FnVarDictionary:
        ...

    @property
    def vardictionary(self) -> FnVarDictionary:
        if self._vd is None:
            xvd = UF.get_function_vars_xnode(
                self.path, self.filename, self.faddr)
            xvard = xvd.find("var-dictionary")
            if xvard is None:
                raise UF.CHBError("Var-dictionary element not found")
            self._vd = self.set_fnvar_dictionary(xvard)
        return self._vd

    @property
    def xprdictionary(self) -> FnXprDictionary:
        return self.vardictionary.xd

    @property
    def invdictionary(self) -> FnInvDictionary:
        if self._id is None:
            xinvnode = UF.get_function_invs_xnode(
                self.path, self.filename, self.faddr)
            xinvd = xinvnode.find("inv-dictionary")
            if xinvd is None:
                raise UF.CHBError("Inv-dictionary element not found")
            self._id = FnInvDictionary(self.vardictionary, xinvd)
        return self._id

    @property
    def invariants(self) -> Mapping[str, Sequence[InvariantFact]]:
        if len(self._invariants) == 0:
            xinvnode = UF.get_function_invs_xnode(
                self.path, self.filename, self.faddr)
            xfacts = xinvnode.find("locations")
            if xfacts is None:
                raise UF.CHBError("Location invariants element not found")
            for xloc in xfacts.findall("loc"):
                xaddr = xloc.get("a")
                xifacts = xloc.get("ifacts")
                if xaddr is not None and xifacts is not None:
                    ifacts = [int(i) for i in xifacts.split(",")]
                    self._invariants[xaddr] = []
                    for ix in ifacts:
                        self._invariants[xaddr].append(
                            self.invdictionary.invariant_fact(ix))
        return self._invariants

    def global_refs(self) -> Tuple[Sequence[XVariable], Sequence[XXpr]]:
        lhsresult: List[XVariable] = []
        rhsresult: List[XXpr] = []

        for instr in self.instructions.values():
            (lhs, rhs) = instr.global_refs()
            lhsresult.extend(lhs)
            rhsresult.extend(rhs)

        return (lhsresult, rhsresult)

    def has_name(self) -> bool:
        return len(self.names) > 0

    @property
    def name(self) -> str:
        if self.has_name:
            return self.names[0]
        else:
            return self.faddr

    @property
    @abstractmethod
    def blocks(self) -> Mapping[str, BasicBlock]:
        ...

    @property
    @abstractmethod
    def instructions(self) -> Mapping[str, Instruction]:
        ...

    @property
    @abstractmethod
    def branchconditions(self) -> Mapping[str, Instruction]:
        ...

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def cfg(self) -> Cfg:
        raise UF.CHBError("Property cfg not implemented for Function")

    def ast(self, astree: AbstractSyntaxTree) -> ASTNode:
        return self.cfg.ast(self, astree)

    def assembly_ast(self, astree: AbstractSyntaxTree) -> ASTNode:
        return self.cfg.assembly_ast(self, astree)

    @abstractmethod
    def strings_referenced(self) -> List[str]:
        ...

    @property
    def md5(self) -> str:
        m = hashlib.md5()
        for instr in self.instructions.values():
            m.update(instr.bytestring.encode("utf-8"))
        return m.hexdigest()

    @property
    def rev_md5(self) -> str:
        """Use reverse bytestring to account for difference in endianness."""

        m = hashlib.md5()
        for instr in self.instructions.values():
            m.update(instr.rev_bytestring.encode("utf-8"))
        return m.hexdigest()

    def block(self, baddr: str) -> BasicBlock:
        if baddr in self.blocks:
            return self.blocks[baddr]
        else:
            raise UF.CHBError("Block " + baddr + " not found in " + self.faddr)

    def load_instructions(self) -> Mapping[str, Sequence[Instruction]]:
        """Return a mapping of block address to instructions that save to memory."""

        result: Dict[str, Sequence[Instruction]] = {}
        for (baddr, b) in self.blocks.items():
            if len(b.load_instructions) > 0:
                result[baddr] = b.load_instructions
        return result

    def store_instructions(self) -> Mapping[str, Sequence[Instruction]]:
        """Return a mapping of block address to instructions that save to memory."""

        result: Dict[str, Sequence[Instruction]] = {}
        for (baddr, b) in self.blocks.items():
            if len(b.store_instructions) > 0:
                result[baddr] = b.store_instructions
        return result

    def call_instructions(self) -> Mapping[str, Sequence[Instruction]]:
        """Return a mapping of block address to instructions that perform a call."""

        result: Dict[str, Sequence[Instruction]] = {}
        for (baddr, b) in self.blocks.items():
            if len(b.call_instructions) > 0:
                result[baddr] = b.call_instructions
        return result

    def has_instruction(self, iaddr: str) -> bool:
        return iaddr in self.instructions

    def instruction(self, iaddr: str) -> Instruction:
        if iaddr in self.instructions:
            return self.instructions[iaddr]
        else:
            raise UF.CHBError("No instruction found at address " + iaddr)

    @abstractmethod
    def to_string(
            self,
            bytes: bool = False,          # instruction bytes
            bytestring: bool = False,     # bytestring of the function
            hash: bool = False,           # md5 of the bytestring
            opcodetxt: bool = True,       # instruction opcode text
            opcodewidth: int = 25,        # alignment width for opcode text
            sp: bool = True) -> str:
        ...
