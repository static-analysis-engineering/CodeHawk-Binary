# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs, LLC
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
import re

from typing import Any, cast, Dict, List, Optional, Sequence, Tuple

from chb.app.BasicBlock import BasicBlock
from chb.app.Function import Function
from chb.app.Instruction import Instruction
from chb.app.StackLayout import StackBuffer

import chb.cmdline.commandutil as UC
from chb.cmdline.XInfo import XInfo

from chb.invariants.XXpr import XXpr, XprCompound, XprConstant

from chb.mips.MIPSInstruction import MIPSInstruction

import chb.util.fileutil as UF


class PatchRecord:

    def __init__(
            self,
            iaddr: str,
            spare: Optional[str],
            faddr: str,
            callee: str,
            args: Sequence[XXpr],
            buffer: StackBuffer,
            fname: Optional[str] = None) -> None:
        self._iaddr = iaddr
        self._spare = spare
        self._faddr = faddr
        self._fname = fname
        self._callee = callee
        self._args = args
        self._buffer = buffer

    @property
    def iaddr(self) -> str:
        return self._iaddr

    @property
    def spare(self) -> Optional[str]:
        return self._spare

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def callee(self) -> str:
        return self._callee

    @property
    def fname(self) -> str:
        if self._fname is not None:
            return self._fname
        else:
            raise UF.CHBError("Function does not have a name: " + self.faddr)

    @property
    def arguments(self) -> Sequence[XXpr]:
        return self._args

    @property
    def buffer(self) -> StackBuffer:
        return self._buffer

    @property
    def formatstring(self) -> Optional[str]:
        if self.callee == "sprintf" and self.arguments[1].is_string_reference:
            return (cast(XprConstant, self.arguments[1])).constant.string_reference()
        else:
            return None

    def has_size(self) -> bool:
        return self.buffer.size() is not None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["faddr"] = self.faddr
        result["iaddr"] = self.iaddr
        if self.spare is not None:
            result["spare"] = self.spare
        if self.buffer.size() is not None:
            result["buffersize"] = self.buffer.size()
        fmtstring = self.formatstring
        if fmtstring is not None:
            result["fmtstring"] = fmtstring
            fspecs = [m.start() for m in re.finditer("%", fmtstring)]
            result["fmtspecs"] = len(fspecs)
        return result


def get_stackbuffer(
        fn: Function,
        ctgt: str,
        instr: Instruction) -> Tuple[Optional[StackBuffer], str]:
    stacklayout = fn.stacklayout()
    if ctgt == "strcpy":
        dstarg = instr.call_arguments[0]
        if dstarg.is_stack_address:
            dstarg = cast(XprCompound, dstarg)
            dstoffset = dstarg.stack_address_offset()
            buffer = stacklayout.stackbuffer(dstoffset)
            return (buffer, "")
    elif ctgt == "sprintf":
        dstarg = instr.call_arguments[0]
        if dstarg.is_stack_address:
            dstarg = cast(XprCompound, dstarg)
            dstoffset = dstarg.stack_address_offset()
            buffer = stacklayout.stackbuffer(dstoffset)
            return (buffer, "")
    return (None, "error")


def has_non_constant_args(ctgt: str, instr: Instruction) -> bool:
    args = instr.call_arguments
    if ctgt == "strcpy":
        return not (args[1].is_string_reference)
    if ctgt == "sprintf":
        if args[1].is_string_reference:
            formatstr = (cast(XprConstant, args[1])).constant.string_reference()
            return "%s" in formatstr
    return False


def find_spare_instruction(
        xinfo: XInfo, block: BasicBlock, iaddr: str) -> Optional[str]:
    if xinfo.is_mips:
        found = None
        for (addr, instr) in block.instructions.items():
            instr = cast(MIPSInstruction, instr)
            if instr.iaddr > iaddr:
                break
            if instr.is_load_instruction:
                if str(instr.operands[0]) == "t9":
                    found = instr.iaddr
        return found
    return None


def get_patch_records(
        path: str,
        xfile: str,
        xinfo: XInfo,
        callees: List[str]) -> List[PatchRecord]:

    app = UC.get_app(path, xfile, xinfo)

    results: Dict[str, PatchRecord] = {}

    for (faddr, blocks) in app.call_instructions().items():
        fn = app.function(faddr)
        for (baddr, instrs) in blocks.items():
            for instr in instrs:
                ctgt = str(instr.call_target)
                if ctgt in callees and has_non_constant_args(ctgt, instr):
                    iaddr = instr.iaddr
                    (buffer, error) = get_stackbuffer(fn, ctgt, instr)
                    if buffer is not None:
                        block = fn.blocks[baddr]
                        spare = find_spare_instruction(xinfo, block, iaddr)
                        results[iaddr] = PatchRecord(
                            iaddr,
                            spare,
                            faddr,
                            ctgt,
                            instr.call_arguments,
                            buffer)

    return list(results.values())
