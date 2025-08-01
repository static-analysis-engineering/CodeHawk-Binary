# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2025  Aarno Labs LLC
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

from typing import Callable, cast, Dict, List, Mapping, Optional, Sequence

from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.BasicBlock import BasicBlock
from chb.app.BDictionary import BDictionary
from chb.app.Function import Function
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.FunctionInfo import FunctionInfo
from chb.app.Cfg import Cfg
from chb.app.StringXRefs import StringsXRefs

from chb.bctypes.BCDictionary import BCDictionary

from chb.invariants.FnVarDictionary import FnVarDictionary
from chb.invariants.FnXprDictionary import FnXprDictionary

from chb.jsoninterface.JSONResult import JSONResult

from chb.pwr.PowerBlock import PowerBlock
from chb.pwr.PowerDictionary import PowerDictionary
from chb.pwr.PowerInstruction import PowerInstruction
from chb.pwr.PowerCfg import PowerCfg

import chb.util.fileutil as UF


class PowerFunction(Function):

    def __init__(
            self,
            path: str,
            filename: str,
            bcd: BCDictionary,
            bd: BDictionary,
            ixd: InterfaceDictionary,
            finfo: FunctionInfo,
            pwrd: PowerDictionary,
            stringsxrefs: StringsXRefs,
            names: Sequence[str],
            xnode: ET.Element) -> None:
        Function.__init__(
            self, path, filename, bcd, bd, ixd, finfo, stringsxrefs, names, xnode)
        self._pwrd = pwrd
        self._cfg: Optional[PowerCfg] = None
        self._blocks: Dict[str, PowerBlock] = {}
        self._instructions: Dict[str, PowerInstruction] = {}
        self._pwrfnd: Optional[FunctionDictionary] = None

    @property
    def pwrdictionary(self) -> PowerDictionary:
        return self._pwrd

    @property
    def pwrfunctiondictionary(self) -> FunctionDictionary:
        if self._pwrfnd is None:
            xfnd = self.xnode.find("instr-dictionary")
            if xfnd is None:
                raise UF.CHBError("Element instr-dictionary missing from xml")
            self._pwrfnd = FunctionDictionary(self, xfnd)
        return self._pwrfnd

    @property
    def blocks(self) -> Mapping[str, PowerBlock]:
        if len(self._blocks) == 0:
            xinstrs = self.xnode.find("instructions")
            if xinstrs is None:
                raise UF.CHBError("Power instructions element missing")
            for n in xinstrs.findall("bl"):
                baddr = n.get("ba")
                if baddr is None:
                    raise UF.CHBError("Power block address missing from xml")
                self._blocks[baddr] = PowerBlock(self, n)
        return self._blocks

    @property
    def instructions(self) -> Mapping[str, PowerInstruction]:
        if len(self._instructions) == 0:
            result: Dict[str, PowerInstruction] = {}

            def f(baddr: str, block: PowerBlock) -> None:
                result.update(block.instructions)

            self.iter_blocks(f)
            return result

        return self._instructions

    def iter_blocks(self, f: Callable[[str, PowerBlock], None]) -> None:
        for (ba, block) in self.blocks.items():
            pwrblock = cast(PowerBlock, block)
            f(ba, pwrblock)

    def iter_instructions(
            self, f: Callable[[str, PowerInstruction], None]) -> None:
        for (ia, instr) in self.instructions.items():
            pwrinstr = cast(PowerInstruction, instr)
            f(ia, pwrinstr)

    @property
    def branchconditions(self) -> Mapping[str, PowerInstruction]:
        result: Dict[str, PowerInstruction] = {}
        for b in self.blocks.values():
            lastinstr = b.last_instruction
            if lastinstr.is_branch_instruction:
                ftconditions = lastinstr.ft_conditions
                if len(ftconditions) > 0:
                    result[b.baddr] = cast(PowerInstruction, lastinstr)
        return result

    def set_fnvar_dictionary(self, xnode: ET.Element) -> FnVarDictionary:
        return FnVarDictionary(self, xnode)

    def strings_referenced(self) -> List[str]:
        result: List[str] = []

        def f(iaddr: str, instr: PowerInstruction) -> None:
            result.extend(instr.strings_referenced)

        self.iter_instructions(f)
        return result

    @property
    def cfg(self) -> Cfg:
        if self._cfg is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("cfg element is missing from power function")
            self._cfg = PowerCfg(self, xcfg)
        return self._cfg

    def byte_string(self, chunksize: Optional[int] = None) -> str:
        s: List[str] = []

        def f(ia: str, i: PowerInstruction) -> None:
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
            typingrules: bool = False,
            stacklayout: bool = False) -> str:
        lines: List[str] = []
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(
                    bytes=bytes,
                    opcodetxt=opcodetxt,
                    opcodewidth=opcodewidth,
                    sp=sp))
            lines.append("-" * 80)
        if bytestring:
            lines.append(self.byte_string(chunksize=80))
        return "\n".join(lines)

    def to_json_result(sefl) -> JSONResult:
        return JSONResult(
            "assemblyfunction", {}, "fail", "not yet implemented for power32")
