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

import xml.etree.ElementTree as ET

from typing import (
    Any, Callable, cast, Dict, List, Mapping, Optional, Sequence, TYPE_CHECKING)

from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.BasicBlock import BasicBlock
from chb.app.BDictionary import BDictionary
from chb.app.Function import Function
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.FunctionInfo import FunctionInfo
from chb.app.Cfg import Cfg
from chb.app.JumpTables import JumpTable
from chb.app.StringXRefs import StringsXRefs

from chb.arm.ARMBlock import ARMBlock
from chb.arm.ARMDictionary import ARMDictionary
from chb.arm.ARMInstruction import ARMInstruction
from chb.arm.ARMJumpTable import ARMJumpTable
from chb.arm.ARMCfg import ARMCfg

from chb.bctypes.BCDictionary import BCDictionary
from chb.bctypes.BCTyp import BCTyp

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnXprDictionary import FnXprDictionary

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.cmdline.PatchResults import PatchEvent


class ARMFunction(Function):

    def __init__(
            self,
            path: str,
            filename: str,
            bcd: BCDictionary,
            bd: BDictionary,
            ixd: InterfaceDictionary,
            finfo: FunctionInfo,
            armd: ARMDictionary,
            stringsxrefs: StringsXRefs,
            names: Sequence[str],
            xnode: ET.Element) -> None:
        Function.__init__(
            self, path, filename, bcd, bd, ixd, finfo, stringsxrefs, names, xnode)
        self._armd = armd
        self._cfg: Optional[ARMCfg] = None
        self._cfg_tc: Optional[ARMCfg] = None
        self._jumptables: Dict[str, JumpTable] = {}
        self._blocks: Dict[str, ARMBlock] = {}
        self._instructions: Dict[str, ARMInstruction] = {}
        self._armfnd: Optional[FunctionDictionary] = None
        self._armfnbtypes: Optional[Dict[str, BCTyp]] = None

    @property
    def armdictionary(self) -> ARMDictionary:
        return self._armd

    @property
    def armfunctiondictionary(self) -> FunctionDictionary:
        if self._armfnd is None:
            xfnd = self.xnode.find("instr-dictionary")
            if xfnd is None:
                raise UF.CHBError("Element instr-dictionary missing from xml")
            self._armfnd = FunctionDictionary(self, xfnd)
        return self._armfnd

    @property
    def btypes(self) -> Dict[str, BCTyp]:
        if self._armfnbtypes is None:
            self._armfnbtypes = {}
            xbtypes = self.xnode.find("btypes")
            if xbtypes is not None:
                for xbt in xbtypes.findall("bt"):
                    xvix = xbt.get("vix")
                    xbix = xbt.get("bix")
                    if xvix is not None and xbix is not None:
                        v = self.xprdictionary.variable(int(xvix))
                        bt = self.bcd.typ(int(xbix))
                        self._armfnbtypes[str(v)] = bt
        return self._armfnbtypes

    def get_cvv_btype(self, cvv: str) -> BCTyp:
        if cvv in self.btypes:
            return self.btypes[cvv]
        else:
            raise UF.CHBError("No type found for " + cvv)

    def has_cvv_btype(self, cvv: str) -> bool:
        return cvv in self.btypes

    @property
    def jumptables(self) -> Dict[str, JumpTable]:
        if len(self._jumptables) == 0:
            xjts = self.xnode.find("jump-tables")
            if xjts is None:
                pass
            else:
                for xjt in xjts.findall("jt"):
                    jumptable = cast(JumpTable, ARMJumpTable(xjt))
                    self._jumptables[jumptable.va] = jumptable
        return self._jumptables

    @property
    def blocks(self) -> Mapping[str, ARMBlock]:
        if len(self._blocks) == 0:
            xinstrs = self.xnode.find("instructions")
            if xinstrs is None:
                raise UF.CHBError("ARM instructions element missing")
            for n in xinstrs.findall("bl"):
                baddr = n.get("ba")
                if baddr is None:
                    raise UF.CHBError("ARM block address missing from xml")
                self._blocks[baddr] = ARMBlock(self, n)
        return self._blocks

    @property
    def instructions(self) -> Mapping[str, ARMInstruction]:
        if len(self._instructions) == 0:
            result: Dict[str, ARMInstruction] = {}

            def f(baddr: str, block: ARMBlock) -> None:
                result.update(block.instructions)

            self.iter_blocks(f)
            return result
        return self._instructions

    def iter_blocks(self, f: Callable[[str, ARMBlock], None]) -> None:
        for (ba, block) in self.blocks.items():
            armblock = cast(ARMBlock, block)
            f(ba, armblock)

    def iter_instructions(self, f: Callable[[str, ARMInstruction], None]) -> None:
        for (ia, instr) in self.instructions.items():
            arminstr = cast(ARMInstruction, instr)
            f(ia, arminstr)

    @property
    def branchconditions(self) -> Mapping[str, ARMInstruction]:
        result: Dict[str, ARMInstruction] = {}
        for b in self.blocks.values():
            lastinstr = b.last_instruction
            if lastinstr.is_branch_instruction:
                ftconditions = lastinstr.ft_conditions
                if len(ftconditions) > 0:
                    result[b.baddr] = cast(ARMInstruction, lastinstr)
        return result

    def set_fnvar_dictionary(self, xnode: ET.Element) -> FnVarDictionary:
        return FnVarDictionary(self, xnode)

    def strings_referenced(self) -> List[str]:
        result: List[str] = []

        def f(iaddr: str, instr: ARMInstruction) -> None:
            result.extend(instr.strings_referenced)

        self.iter_instructions(f)
        return result

    @property
    def cfg(self) -> Cfg:
        if self._cfg is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("cfg element is missing from arm function")
            self._cfg = ARMCfg(self, xcfg)
        return self._cfg

    def cfg_tc(self, patchevents: Dict[str, "PatchEvent"] = {}) -> ARMCfg:
        """Return a CFG with trampoline collapsed."""

        if self._cfg_tc is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("cfg element is missing from arm function")
            self._cfg_tc = ARMCfg(self, xcfg, patchevents)
        return self._cfg_tc

    def byte_string(self, chunksize: Optional[int] = None) -> str:
        s: List[str] = []

        def f(ia: str, i: ARMInstruction) -> None:
            s.extend(i.bytestring)

        self.iter_instructions(f)
        if chunksize is None:
            return "".join(s)
        else:
            result = "".join(s)
            size = len(s)
            chunks = [result[i:i+chunksize] for i in range(0, size, chunksize)]
            return "\n".join(chunks)

    def to_string(
            self,
            bytes: bool = False,
            bytestring: bool = False,
            hash: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 40,
            sp: bool = True,
            proofobligations: bool = False,
            stacklayout: bool = False) -> str:
        lines: List[str] = []
        if stacklayout:
            lines.append(str(self.stacklayout()))
            lines.append(" ")
        if proofobligations:
            lines.append(str(self.proofobligations))
            lines.append(".~" * 40)
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(
                    bytes=bytes,
                    opcodetxt=opcodetxt,
                    opcodewidth=opcodewidth,
                    sp=sp))
            lines.append("-" * 80)
        if hash:
            lines.append("hash: " + self.md5)
        if bytestring:
            lines.append(self.byte_string(chunksize=80))
        return "\n".join(lines)

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        if len(self.names) > 0:
            content["name"] = self.names[0]
        content["faddr"] = self.faddr
        content["md5hash"] = self.md5
        content["basicblocks"] = blocks = []
        for b in self.blocks.values():
            bresult = b.to_json_result()
            if not bresult.is_ok:
                return JSONResult("assemblyfunction", {}, "fail", bresult.reason)
            else:
                blocks.append(bresult.content)
        return JSONResult("assemblyfunction", content, "ok")
