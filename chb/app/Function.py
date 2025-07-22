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
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    NewType,
    Optional,
    Sequence,
    TYPE_CHECKING,
    Tuple,
    Union)

from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.BasicBlock import BasicBlock
from chb.app.BDictionary import BDictionary
from chb.app.Cfg import Cfg
from chb.app.FnProofObligations import FnProofObligations
from chb.app.FnXPODictionary import FnXPODictionary
from chb.app.FunctionInfo import FunctionInfo
from chb.app.GlobalMemoryMap import (
    GlobalLoad, GlobalStore, GlobalAddressArgument)
from chb.app.Instruction import Instruction
from chb.app.JumpTables import JumpTable
from chb.app.StackLayout import StackLayout
from chb.app.StringXRefs import StringsXRefs

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.bctypes.BCDictionary import BCDictionary

from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnVarInvDictionary import FnVarInvDictionary
from chb.invariants.FnXprDictionary import FnXprDictionary
from chb.invariants.InvariantFact import InvariantFact, InitialVarDisEqualityFact
from chb.invariants.VarInvariantFact import VarInvariantFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.jsoninterface.JSONResult import JSONResult

from chb.userdata.UserHints import UserHints

import chb.util.fileutil as UF
from chb.util.graphutil import coalesce_lists
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.FnStackFrame import FnStackFrame
    from chb.app.GlobalMemoryMap import (
        GlobalMemoryMap, GlobalLocation, GlobalReference)
    from chb.bctypes.BCTyp import BCTyp


class Function(ABC):

    def __init__(
            self,
            path: str,
            filename: str,
            bcd: BCDictionary,
            bd: BDictionary,
            ixd: InterfaceDictionary,
            finfo: FunctionInfo,
            stringsxrefs: StringsXRefs,
            names: Sequence[str],
            xnode: ET.Element) -> None:
        self.xnode = xnode
        self._path = path
        self._filename = filename
        self._bcd = bcd
        self._bd = bd
        self._ixd = ixd
        self._finfo = finfo
        self._stringsxrefs = stringsxrefs
        self._names = names
        self._vd: Optional[FnVarDictionary] = None
        self._id: Optional[FnInvDictionary] = None
        self._xpod: Optional[FnXPODictionary] = None
        self._varinvd: Optional[FnVarInvDictionary] = None
        self._invariants: Dict[str, List[InvariantFact]] = {}
        self._varinvariants: Dict[str, List[VarInvariantFact]] = {}
        self._stacklayout: Optional[StackLayout] = None
        self._globalrefs: Optional[Dict[str, List["GlobalReference"]]] = None
        self._proofobligations: Optional[FnProofObligations] = None

    @property
    def path(self) -> str:
        return self._path

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def app(self) -> "AppAccess":
        return self.ixd.app

    @property
    def bd(self) -> BDictionary:
        return self._bd

    @property
    def bcd(self) -> BCDictionary:
        return self._bcd

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
    def xpodictionary(self) -> FnXPODictionary:
        if self._xpod is None:
            xxpod = self.xnode.find("xpodictionary")
            if xxpod is None:
                raise UF.CHBError("XPO dictionary element not found")
            self._xpod = FnXPODictionary(self, xxpod)
        return self._xpod

    @property
    def proofobligations(self) -> FnProofObligations:
        if self._proofobligations is None:
            xprf = self.xnode.find("proofobligations")
            if xprf is None:
                raise UF.CHBError("Proof obligations element not found")
            self._proofobligations = FnProofObligations(self, xprf)
        return self._proofobligations

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
    def varinvdictionary(self) -> FnVarInvDictionary:
        if self._varinvd is None:
            if UF.has_function_varinvs_file(
                    self.path, self.filename, self.faddr):
                xvarinvnode = UF.get_function_varinvs_xnode(
                    self.path, self.filename, self.faddr)
                xvarinvd = xvarinvnode.find("varinv-dictionary")
                if xvarinvd is None:
                    raise UF.CHBError("VarInv-dictionary element not found")
                self._varinvd = FnVarInvDictionary(self.vardictionary, xvarinvd)
            else:
                self._varinvd = FnVarInvDictionary(self.vardictionary, None)
        return self._varinvd

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

    def has_var_disequality(self, loc: str, v: XVariable) -> bool:
        locinv = self.invariants.get(loc, [])
        for inv in locinv:
            if inv.is_initial_var_disequality:
                inv = cast(InitialVarDisEqualityFact, inv)
                if (
                        inv.variable.name == v.name
                        or inv.initial_value.name == v.name):
                    return True
        return False

    @property
    def var_invariants(self) -> Mapping[str, Sequence[VarInvariantFact]]:
        if (
                UF.has_function_varinvs_file(
                    self.path, self.filename, self.faddr)
                and len(self._varinvariants) == 0):
            xvarinvnode = UF.get_function_varinvs_xnode(
                self.path, self.filename, self.faddr)
            xvarfacts = xvarinvnode.find("locations")
            if xvarfacts is None:
                raise UF.CHBError("Location var-invariants element not found")
            for xloc in xvarfacts.findall("loc"):
                xaddr = xloc.get("a")
                xvfacts = xloc.get("ivfacts")
                if xaddr is not None and xvfacts is not None:
                    vfacts = [int(i) for i in xvfacts.split(",")]
                    self._varinvariants[xaddr] = []
                    for ix in vfacts:
                        self._varinvariants[xaddr].append(
                            self.varinvdictionary.var_invariant_fact(ix))
        return self._varinvariants

    @property
    def jumptables(self) -> Dict[str, JumpTable]:
        return {}

    def has_jumptable(self, va: str) -> bool:
        return va in self.jumptables

    def get_jumptable(self, va: str) -> JumpTable:
        if self.has_jumptable(va):
            return self.jumptables[va]
        else:
            raise UF.CHBError("No jumptable found at address " + va)

    def global_refs(self) -> Tuple[Sequence[XVariable], Sequence[XXpr]]:
        lhsresult: List[XVariable] = []
        rhsresult: List[XXpr] = []

        for instr in self.instructions.values():
            (lhs, rhs) = instr.global_refs()
            lhsresult.extend(lhs)
            rhsresult.extend(rhs)

        return (lhsresult, rhsresult)

    def lhs_variables(
            self, filter: Callable[[XVariable], bool]) -> List[XVariable]:
        result: List[XVariable] = []
        for instr in self.instructions.values():
            try:
                result.extend(instr.lhs_variables(filter))
            except Exception as e:
                raise UF.CHBError(
                    "Error in lhs variables in instruction "
                    + instr.iaddr
                    + " ("
                    + instr.mnemonic
                    + "): "
                    + str(e))
        return result

    def rhs_expressions(self, filter: Callable[[XXpr], bool]) -> List[XXpr]:
        result: List[XXpr] = []
        for instr in self.instructions.values():
            try:
                result.extend(instr.rhs_expressions(filter))
            except Exception as e:
                raise UF.CHBError(
                    "Error in rhs expressions in instruction "
                    + instr.iaddr
                    + " ("
                    + instr.mnemonic
                    + "): "
                    + str(e))
        return result

    def has_name(self) -> bool:
        return len(self.names) > 0

    @property
    def name(self) -> str:
        if self.has_name():
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
    def function_extent(self) -> Tuple[str, str]:
        fmin: int = 100000000
        fmax: int = 0
        for b in self.blocks.values():
            if int(b.baddr, 16) < fmin:
                fmin = int(b.baddr, 16)
            if int(b.lastaddr, 16) > fmax:
                fmax = int(b.lastaddr, 16)
        return (hex(fmin), hex(fmax))

    def within_function_extent(self, addr: str) -> bool:
        (fmin, fmax) = self.function_extent
        return (
            (int(fmin, 16) <= int(addr, 16))
            and (int(addr, 16) <= int(fmax, 16)))

    @property
    def cfg(self) -> Cfg:
        raise UF.CHBError("Property cfg not implemented for Function")

    @property
    def stackframe(self) -> "FnStackFrame":
        raise UF.CHBError("Property stackframe not implemented for Function")

    @property
    def register_lhs_types(self) -> Dict[str, Dict[str, "BCTyp"]]:
        """Return a mapping from instr. addr. to register to variable type.

        Contains the inferred types of register left-hand sides that may be
        converted to ssa variables in the lifting.
        """
        raise UF.CHBError(
            "Property register_lhs_types not implemented for Function")

    def register_lhs_type(self, iaddr: str, reg: str) -> Optional["BCTyp"]:
        """Return the type of the register reg assigned at address iaddr."""

        return None

    @property
    def lhs_names(self) -> Dict[str, str]:
        return self.finfo.lhs_names

    @property
    def stack_variable_types(self) -> Dict[int, "BCTyp"]:
        """Return a mapping from stack offset to stack variable type.

        Contains the inferred types of stack variables, including both stack-
        allocated arrays and regular stack variables.
        """
        raise UF.CHBError(
            "Property stack_variable_types not implemented for Function")

    def stack_variable_type(self, offset: int) -> Optional["BCTyp"]:
        """Return the type of the stack variable at stack offset offset. """

        return None

    @abstractmethod
    def strings_referenced(self) -> List[str]:
        ...

    @property
    def md5(self) -> str:
        m = hashlib.md5()
        for instr in self.instructions.values():
            m.update(instr.bytestring.encode("utf-8"))
        return m.hexdigest()

    def mnemonic_stats(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for i in self.instructions.values():
            mnemonic = i.mnemonic_stem
            result.setdefault(mnemonic, 0)
            result[mnemonic] += 1
        return result

    def mnemonic_string(self) -> str:
        s: str = ""
        for (iaddr, i) in sorted(self.instructions.items()):
            s += i.mnemonic
        return s

    @property
    def mnemonic_string_md5(self) -> str:
        m = hashlib.md5()
        m.update(self.mnemonic_string().encode("utf-8"))
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

    def jump_instructions(self) -> Mapping[str, Sequence[Instruction]]:
        """Return a mapping of block address to instructions that perform a jump."""

        result: Dict[str, Sequence[Instruction]] = {}
        for (baddr, b) in self.blocks.items():
            if len(b.jump_instructions) > 0:
                result[baddr] = b.jump_instructions
        return result

    def has_instruction(self, iaddr: str) -> bool:
        return iaddr in self.instructions

    def instruction(self, iaddr: str) -> Instruction:
        if iaddr in self.instructions:
            return self.instructions[iaddr]
        else:
            raise UF.CHBError("No instruction found at address " + iaddr)

    def rdef_locations(self) -> Dict[str, List[List[str]]]:
        result: Dict[str, List[List[str]]] = {}

        for (iaddr, instr) in self.instructions.items():
            irdefs = instr.rdef_locations()
            for (reg, rdeflists) in irdefs.items():
                result.setdefault(reg, [])
                result[reg].extend(rdeflists)
        return result

    def lhs_types(self) -> Dict[str, Dict[str, "BCTyp"]]:
        """Return a mapping from iaddr to lhs name to type."""

        result: Dict[str, Dict[str, "BCTyp"]] = {}

        for (iaddr, instr) in self.instructions.items():
            ilhs_types = instr.lhs_types()
            result[iaddr] = {}
            for (vname, vtype) in ilhs_types.items():
                result[iaddr][vname] = vtype

        return result

    def stacklayout(self) -> StackLayout:
        if self._stacklayout is None:
            stacklayout = StackLayout()
            for (iaddr, instr) in self.instructions.items():
                memaccesses = instr.memory_accesses
                if any(a.is_stack_address for a in memaccesses):
                    stacklayout.add_access(instr)
                if instr.is_call_instruction:
                    stacklayout.add_access(instr)
            self._stacklayout = stacklayout
        return self._stacklayout

    def globalrefs(self) -> Dict[str, List["GlobalReference"]]:
        if self._globalrefs is None:
            self._globalrefs = {}
            gnode = self.xnode.find("global-references")
            if gnode is not None:
                glnode = gnode.find("location-references")
                if glnode is not None:
                    for rnode in glnode.findall("gref"):
                        gaddr = rnode.get("g")
                        if gaddr is None:
                            chklogger.logger.error(
                                "Global address is missing in xml gref")
                            continue
                        gloc = self.app.globalmemorymap.get_location(gaddr)
                        if gloc is None:
                            chklogger.logger.error(
                                "Global location is missing for %s", gaddr)
                            continue
                        gt = rnode.get("t")
                        if gt is None:
                            chklogger.logger.error(
                                "Global reference type is missing for %s", gaddr)
                            continue
                        if gt == "L":
                            gref: "GlobalReference" = GlobalLoad(self, gloc, rnode)
                        elif gt == "S":
                            gref = GlobalStore(self, gloc, rnode)
                        elif gt == "CA":
                            gref = GlobalAddressArgument(self, gloc, rnode)
                        else:
                            chklogger.logger.error(
                                "Global reference type %s not recognized for %s",
                                gt, gaddr)
                            continue
                        self._globalrefs.setdefault(gaddr, [])
                        self._globalrefs[gaddr].append(gref)
        return self._globalrefs

    @abstractmethod
    def to_string(
            self,
            bytes: bool = False,          # instruction bytes
            bytestring: bool = False,     # bytestring of the function
            hash: bool = False,           # md5 of the bytestring
            opcodetxt: bool = True,       # instruction opcode text
            opcodewidth: int = 25,        # alignment width for opcode text
            sp: bool = True,
            proofobligations: bool = False,
            typingrules: bool = False,
            stacklayout: bool = False) -> str:
        ...

    @abstractmethod
    def to_json_result(self) -> JSONResult:
        ...
