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

import hashlib
import xml.etree.ElementTree as ET

from typing import Callable, cast, Dict, List, Mapping, Optional, Sequence, Tuple

from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.BasicBlock import BasicBlock
from chb.app.BDictionary import BDictionary
from chb.app.Cfg import Cfg
from chb.app.Function import Function
from chb.app.FunctionInfo import FunctionInfo
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.StringXRefs import StringsXRefs

from chb.bctypes.BCDictionary import BCDictionary

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnInvDictionary import FnInvDictionary
from chb.invariants.FnInvariants import FnInvariants
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.jsoninterface.JSONResult import JSONResult

from chb.mips.MIPSDictionary import MIPSDictionary
from chb.mips.MIPSBlock import MIPSBlock
from chb.mips.MIPSCfg import MIPSCfg
from chb.mips.MIPSInstruction import MIPSInstruction

from chb.models.ModelsAccess import ModelsAccess

import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF


class MIPSFunction(Function):

    def __init__(self,
                 path: str,
                 filename: str,
                 bcd: BCDictionary,
                 bd: BDictionary,
                 ixd: InterfaceDictionary,
                 finfo: FunctionInfo,
                 mipsd: MIPSDictionary,
                 stringsxrefs: StringsXRefs,
                 names: Sequence[str],
                 models: ModelsAccess,
                 xnode: ET.Element) -> None:
        Function.__init__(
            self, path, filename, bcd, bd, ixd, finfo, stringsxrefs, names, xnode)
        self._mipsd = mipsd
        self._models = models
        self._blocks: Dict[str, MIPSBlock] = {}
        self._cfg: Optional[MIPSCfg] = None
        self._mipsfnd: Optional[FunctionDictionary] = None
        self._addressreference: Dict[str, str] = {}

    @property
    def models(self) -> ModelsAccess:
        return self._models

    @property
    def dictionary(self) -> MIPSDictionary:
        return self._mipsd

    @property
    def functiondictionary(self) -> FunctionDictionary:
        if self._mipsfnd is None:
            xfnd = self.xnode.find("instr-dictionary")
            if xfnd is None:
                raise UF.CHBError("Element instr-dictionary missing from xml")
            self._mipsfnd = FunctionDictionary(self, xfnd)
        return self._mipsfnd

    @property
    def blocks(self) -> Dict[str, MIPSBlock]:
        if len(self._blocks) == 0:
            xinstrs = self.xnode.find("instructions")
            if xinstrs is None:
                raise UF.CHBError(
                    "Xml element instructions missing from function xml")
            for b in xinstrs.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Block address is missing from xml")
                self._blocks[baddr] = MIPSBlock(self, b)
        return self._blocks

    @property
    def instructions(self) -> Mapping[str, MIPSInstruction]:
        result: Dict[str, MIPSInstruction] = {}

        def f(baddr: str, block: MIPSBlock) -> None:
            result.update(block.instructions)

        self.iter_blocks(f)
        return result

    def iter_blocks(self, f: Callable[[str, MIPSBlock], None]) -> None:
        for (ba, block) in self.blocks.items():
            mipsblock = cast(MIPSBlock, block)
            f(ba, mipsblock)

    def iter_instructions(self, f: Callable[[str, MIPSInstruction], None]) -> None:
        for (ia, instr) in self.instructions.items():
            mipsinstr = cast(MIPSInstruction, instr)
            f(ia, mipsinstr)

    @property
    def branchconditions(self) -> Mapping[str, MIPSInstruction]:
        result: Dict[str, MIPSInstruction] = {}
        for b in self.blocks.values():
            lastinstr = b.last_instruction
            if lastinstr.is_branch_instruction:
                ftconditions = lastinstr.ft_conditions
                if len(ftconditions) > 0:
                    result[b.baddr] = cast(MIPSInstruction, lastinstr)
        return result

    def set_fnvar_dictionary(self, xnode: ET.Element) -> FnVarDictionary:
        return FnVarDictionary(self, xnode)

    @property
    def cfg(self) -> MIPSCfg:
        if self._cfg is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("Element cfg missing from function xml")
            self._cfg = MIPSCfg(self, xcfg)
        return self._cfg

    @property
    def address_reference(self) -> Mapping[str, str]:
        """Return map of addr -> block addr."""

        if len(self._addressreference) == 0:
            result: Dict[str, str] = {}

            def add(baddr: str, block: MIPSBlock) -> None:
                for a in block.instructions:
                    result[a] = baddr

            self.iter_blocks(add)
            self._addressreference = result
        return self._addressreference

    def byte_string(self, chunksize: Optional[int] = None) -> str:
        s: List[str] = []

        def f(ia: str, i: MIPSInstruction) -> None:
            s.extend(i.bytestring)

        self.iter_instructions(f)
        if chunksize is None:
            return ''.join(s)
        else:
            sresult = ''.join(s)
            size = len(sresult)
            chunks = [sresult[i: i + chunksize] for i in range(0, size, chunksize)]
            return '\n'.join(chunks)

    def calls_to_app_function(self, tgtaddr: str) -> List[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            if instr.is_call_to_app_function(tgtaddr):
                result.append(instr)

        self.iter_instructions(f)
        return result

    def load_word_instructions(self) -> List[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            if instr.is_load_word_instruction:
                result.append(instr)

        self.iter_instructions(f)
        return result

    def store_word_instructions(self) -> List[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            if instr.is_store_word_instruction:
                result.append(instr)

        self.iter_instructions(f)
        return result

    def restore_register_instructions(self) -> List[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            if instr.is_restore_register_instruction:
                result.append(instr)

        self.iter_instructions(f)
        return result

    def call_instructions_to_target(self, tgt: str) -> List[MIPSInstruction]:
        """Returns a list of instructions that are calls to the given function."""
        result: List[MIPSInstruction] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            if instr.is_call_instruction:
                if str(instr.call_target) == tgt:
                    result.append(instr)

        self.iter_instructions(f)
        return result

    def global_refs(self) -> Tuple[List[XVariable], List[XXpr]]:
        lhsresult: List[XVariable] = []
        rhsresult: List[XXpr] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            (lhs, rhs) = instr.global_refs()
            lhsresult.extend(lhs)
            rhsresult.extend(rhs)

        self.iter_instructions(f)
        return (lhsresult, rhsresult)

    def strings_referenced(self) -> List[str]:
        result: List[str] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            result.extend(instr.strings_referenced)

        self.iter_instructions(f)
        return result

    # returns a dictionary of gvar -> count
    def global_variables(self) -> Dict[str, int]:
        result: Dict[str, int] = {}

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            iresult = instr.global_variables()
            for gv in iresult:
                result.setdefault(gv, 0)
                result[gv] += iresult[gv]

        self.iter_instructions(f)
        return result

    # returns a dictionary of registers used in the function (name -> variable)
    def registers(self) -> Dict[str, str]:
        result: Dict[str, str] = {}

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            iresult = instr.registers()
            for r in iresult:
                result.setdefault(r, iresult[r])

        self.iter_instructions(f)
        return result

    def return_instructions(self) -> List[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(iaddr: str, instr: MIPSInstruction) -> None:
            if instr.is_return_instruction:
                result.append(instr)

        self.iter_instructions(f)
        return result

    def jump_conditions(self) -> Dict[str, Dict[str, str]]:
        return self.cfg.conditions()

    def to_sliced_string(self, registers: List[str]) -> str:
        lines: List[str] = []
        for b in sorted(self.blocks):
            looplevels = self.cfg.loop_levels(self.blocks[b].baddr)
            blocklines = self.blocks[b].to_sliced_string(registers, len(looplevels))
            if len(blocklines) > 0:
                lines.append(blocklines)
            else:
                lines.append(
                    str(self.blocks[b].baddr).rjust(10)
                    + ' '
                    + ('L' * len(looplevels)))
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
        if stacklayout:
            lines.append(str(self.stacklayout()))
            lines.append(" ")
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(
                    bytes=bytes,
                    opcodetxt=opcodetxt,
                    opcodewidth=opcodewidth,
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
            "assemblyfunction", {}, "fail", "not yet implemented for MIPS")
