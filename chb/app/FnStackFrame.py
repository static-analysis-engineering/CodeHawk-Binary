# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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
"""Stackframe layout obtained from the ocaml analyzer."""

import xml.etree.ElementTree as ET

from typing import cast, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.app.Register import Register
from chb.invariants.FnStackAccess import FnStackAccess, FnStackStore

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.invariants.FnVarDictionary import FnVarDictionary


class FnSavedRegister:

    def __init__(self, reg: Register, xnode: ET.Element) -> None:
        self._reg = reg
        self._xnode = xnode

    @property
    def register(self) -> Register:
        return self._reg

    @property
    def save_locations(self) -> List[str]:
        xsave = self._xnode.get("save")
        if xsave is None:
            return []
        else:
            return xsave.split(";")

    @property
    def restore_locations(self) -> List[str]:
        xrestore = self._xnode.get("restore")
        if xrestore is None:
            return []
        else:
            return xrestore.split(";")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("register: " + str(self.register))
        lines.append("  save locations: " + ", ".join(self.save_locations))
        lines.append("  restore locations: " + ", ".join(self.restore_locations))
        return "\n".join(lines)


class FnStackBuffer:

    def __init__(self, offset: int, size: int) -> None:
        self._offset = offset
        self._size = size

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> int:
        return self._size

    def __str__(self) -> str:
        return f"{self.offset}: {self.size}"


class LogicalStackBuffer:

    def __init__(self, offset: int) -> None:
        self._offset = offset
        self._buffers: List[FnStackBuffer] = []
        self._zeroing: bool = False
        self._support: List[str] = []

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> int:
        return sum(b.size for b in self.buffers)

    @property
    def buffers(self) -> List[FnStackBuffer]:
        return self._buffers

    def add_buffer(self, b: FnStackBuffer) -> None:
        self._buffers.append(b)

    def set_zeroing(self) -> None:
        self._zeroing = True

    @property
    def support(self) -> List[str]:
        return self._support

    @property
    def is_zeroing(self) -> bool:
        return self._zeroing

    def add_support(self, iaddrs: List[str]) -> None:
        self._support.extend(iaddrs)

    def has_support(self) -> bool:
        return self.is_zeroing or len(self.support) > 0


class FnStackFrame:

    def __init__(self, fn: "Function", xnode: ET.Element) -> None:
        self._fn = fn
        self._xnode = xnode
        self._savedregisters: Dict[str, FnSavedRegister] = {}
        self._accesses: Dict[int, List[Tuple[str, FnStackAccess]]] = {}

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def bd(self) -> "BDictionary":
        return self.function.bd

    @property
    def vard(self) -> "FnVarDictionary":
        return self.function.vardictionary

    @property
    def saved_registers(self) -> Dict[str, FnSavedRegister]:
        if len(self._savedregisters) == 0:
            srnode = self._xnode.find("saved-registers")
            if srnode is not None:
                for xrs in srnode.findall("sr"):
                    reg = self.bd.read_xml_register(xrs)
                    sr = FnSavedRegister(reg, xrs)
                    self._savedregisters[str(reg)] = sr
        return self._savedregisters

    @property
    def accesses(self) -> Dict[int, List[Tuple[str, FnStackAccess]]]:
        if len(self._accesses) == 0:
            sanode = self._xnode.find("stack-accesses")
            if sanode is not None:
                for xoff in sanode.findall("offset"):
                    offset = xoff.get("n")
                    if offset is not None:
                        stackoffset = int(offset)
                        offsetacc: List[Tuple[str, FnStackAccess]] = []
                        self._accesses[stackoffset] = offsetacc
                        for xsa in xoff.findall("sa"):
                            iaddr = xsa.get("addr", "0x0")
                            sa = self.vard.read_xml_stack_access(xsa)
                            offsetacc.append((iaddr, sa))
        return self._accesses

    def get_stack_buffer(self, offset: int) -> Optional[LogicalStackBuffer]:
        for b in self.logical_layout():
            if b.offset == offset:
                return b
        return None

    def offset_layout(self) -> List[Tuple[FnStackBuffer, int]]:
        result: List[Tuple[FnStackBuffer, int]] = []
        offsets = sorted(list(self.accesses.keys()))
        for i in range(0, len(offsets) - 1):
            buffer = FnStackBuffer(offsets[i], offsets[i+1] - offsets[i])
            known: int = 0
            isgreater: int = 0
            isless: int = 0
            for (_, acc) in self.accesses[buffer.offset]:
                if acc.size is None:
                    known = 4
                else:
                    if acc.size > buffer.size:
                        isgreater = 2
                    elif acc.size < buffer.size:
                        isless = 1
            score = known + isless + isgreater
            result.append((buffer, score))
        return result

    def is_zeroed_buffer(self, offset: int) -> bool:
        has_blockwrite: bool = False
        has_zerowrite: bool = False
        for (_, acc) in self.accesses[offset]:
            if acc.is_block_write:
                has_blockwrite = True
            elif acc.is_store:
                acc = cast(FnStackStore, acc)
                if str(acc.value) == "0x0":
                    has_zerowrite = True
        return has_blockwrite and has_zerowrite

    def is_zeroing_buffer(self, offset: int) -> bool:
        for (_, acc) in self.accesses[offset]:
            if acc.is_store:
                acc = cast(FnStackStore, acc)
                if str(acc.value) == "0x0":
                    continue
                else:
                    return False
            else:
                return False
        return True

    def size_support(self, b: FnStackBuffer) -> List[str]:
        result: List[str] = []
        size = b.size
        for (iaddr, acc) in self.accesses[b.offset]:
            if acc.is_block_write or acc.is_block_read:
                if acc.size is not None:
                    if acc.size == b.size:
                        result.append(iaddr + ":size")
        return result

    def spill_support(self, b: FnStackBuffer) -> List[str]:
        result: List[str] = []
        for (iaddr, acc) in self.accesses[b.offset]:
            if acc.is_register_spill:
                result.append(iaddr + ":spill")
        return result

    def logical_layout(self) -> List[LogicalStackBuffer]:
        result: List[LogicalStackBuffer] = []
        offsetlayout = self.offset_layout()
        bcount = len(offsetlayout)
        i: int = 0
        activebuffer: Optional[LogicalStackBuffer] = None
        while i < bcount:
            (b, _) = offsetlayout[i]
            activebuffer = LogicalStackBuffer(b.offset)
            activebuffer.add_support(self.size_support(b))
            activebuffer.add_buffer(b)
            if (i + 1) < bcount:
                (nxtbuf, _) = offsetlayout[i + 1]
                activebuffer.add_support(self.spill_support(nxtbuf))
            if self.is_zeroed_buffer(b.offset):
                activebuffer.set_zeroing()
                i += 1
                while (i < bcount):
                    (b, _) = offsetlayout[i]
                    if self.is_zeroing_buffer(b.offset):
                        activebuffer.add_buffer(b)
                        i += 1
                    else:
                        break
                result.append(activebuffer)
            else:
                result.append(activebuffer)
                i += 1
        return result

    def logical_layout_obsolete(self) -> List[LogicalStackBuffer]:
        result: List[LogicalStackBuffer] = []
        activebuffer: Optional[LogicalStackBuffer] = None
        for (b, _) in self.offset_layout():
            if activebuffer is None:
                activebuffer = LogicalStackBuffer(b.offset)
                activebuffer.add_support(self.size_support(b))
                activebuffer.add_buffer(b)
                if self.is_zeroed_buffer(b.offset):
                    activebuffer.set_zeroing()
                else:
                    result.append(activebuffer)
                    activebuffer = None
            else:
                if self.is_zeroing_buffer(b.offset):
                    activebuffer.add_buffer(b)
                else:
                    result.append(activebuffer)
                    activebuffer = LogicalStackBuffer(b.offset)
                    activebuffer.add_support(self.size_support(b))
                    activebuffer.add_buffer(b)
                    if self.is_zeroed_buffer(b.offset):
                        activebuffer.set_zeroing()
                    else:
                        result.append(activebuffer)
                        activebuffer is None
        return result

    def buffer_partition(self) -> Dict[int, int]:
        result: Dict[int, int] = {}
        for (b, _) in self.offset_layout():
            known: int = 0
            isgreater: int = 0
            isless: int = 0
            for (_, acc) in self.accesses[b.offset]:
                if acc.size is None:
                    known = 4
                else:
                    if acc.size > b.size:
                        isgreater = 2
                    elif acc.size < b.size:
                        isless = 1
            score = known + isless + isgreater
            result.setdefault(score, 0)
            result[score] += 1
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for offset in sorted(self.accesses):
            lines.append(str(offset))
            offsetacc = self.accesses[offset]
            for (iaddr, acc) in offsetacc:
                lines.append("  " + iaddr + ": " + str(acc))
        return "\n".join(lines)
