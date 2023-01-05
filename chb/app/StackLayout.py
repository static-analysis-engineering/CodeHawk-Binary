# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Represents the artifacts that contribute to constructing a stack layout."""


from abc import ABC, abstractmethod

from typing import cast, Dict, List, Optional, Tuple, TYPE_CHECKING

from chb.app.Instruction import Instruction
from chb.app.MemoryAccess import MemoryAccess, RegisterSpill, RegisterRestore
from chb.app.Register import Register
from chb.app.StackPointerOffset import StackPointerOffset

if TYPE_CHECKING:
    from chb.invariants.XBound import XBound


class StackAccess:
    """Collects reads, writes, and escapes at a particular offset."""

    def __init__(self, offset: int, size: Optional[int] = None) -> None:
        self._offset = offset
        self._size = size      # size in bytes
        self._reads: List[Instruction] = []
        self._writes: List[Instruction] = []
        self._escapes: List[Instruction] = []

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> Optional[int]:
        return self._size

    @property
    def reads(self) -> List[Instruction]:
        return self._reads

    @property
    def writes(self) -> List[Instruction]:
        return self._writes

    @property
    def escapes(self) -> List[Instruction]:
        return self._escapes

    def update_size(self, size: int) -> None:
        if self.size is None or size > self.size:
            self._size = size

    def add_read(self, instr: Instruction) -> None:
        self._reads.append(instr)

    def add_write(self, instr: Instruction) -> None:
        self._writes.append(instr)

    def add_escape(self, instr: Instruction) -> None:
        self._escapes.append(instr)

    def __str__(self) -> str:
        lines: List[str] = []
        psize = " (" + str(self.size) + ")" if self.size is not None else ""
        lines.append(str(self.offset) + psize)
        if len(self.reads) > 0:
            lines.append("  Reads:")
            for r in self.reads:
                lines.append("    " + r.iaddr + "  " + r.annotation)
        if len(self.writes) > 0:
            lines.append("  Writes:")
            for w in self.writes:
                lines.append("    " + w.iaddr + "  " + w.annotation)
        if len(self.escapes) > 0:
            lines.append("  Escapes:")
            for e in self.escapes:
                lines.append("    " + e.iaddr + "  " + e.annotation)
        return "\n".join(lines)


class SavedRegister:

    def __init__(self, r: str, offset: int) -> None:
        self._register = r
        self._offset = offset
        self._spills: List[Instruction] = []
        self._restores: List[Instruction] = []

    @property
    def register(self) -> str:
        return self._register

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def spills(self) -> List[Instruction]:
        return self._spills

    @property
    def restores(self) -> List[Instruction]:
        return self._restores

    def add_spill(self, i: Instruction) -> None:
        self._spills.append(i)

    def add_restore(self, i: Instruction) -> None:
        self._restores.append(i)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(str(self.offset).rjust(5) + "  " + str(self.register))
        lines.append("  spills:")
        for instr in self.spills:
            lines.append("     " + instr.iaddr + "  " + instr.annotation)
        lines.append("  restores:")
        for instr in self.restores:
            lines.append("     " + instr.iaddr + "  " + instr.annotation)
        return "\n".join(lines)


class StackBuffer:
    """A contiguous stack region that can be read/written as a unit."""

    def __init__(
            self,
            offset: int,
            lb: Optional[int] = None,
            ub: Optional[int] = None) -> None:
        self._offset = offset
        self._lb = lb
        self._ub = ub
        self._accesses: List[StackAccess] = []

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def upperbound(self) -> Optional[int]:
        return self._ub

    @property
    def lowerbound(self) -> Optional[int]:
        return self._lb

    def maxsize(self) -> Optional[int]:
        if self.upperbound is not None:
            return self.upperbound - self.offset
        return None

    def minsize(self) -> Optional[int]:
        if self.lowerbound is not None:
            return self.lowerbound - self.offset
        return None

    def size(self) -> Optional[int]:
        if self.upperbound is None or self.lowerbound is None:
            return None
        if self.upperbound != self.lowerbound:
            return None
        return self.maxsize()


class StackLayout:

    def __init__(self) -> None:
        self._size = 0
        self._offsets: Dict[str, StackPointerOffset] = {}
        self._accesses: List[Instruction] = []
        self._saved_registers: Dict[Tuple[str, int], SavedRegister] = {}
        self._layout: Dict[int, StackAccess] = {}

    @property
    def size(self) -> int:
        if self._size == 0:
            self._compute_size()
        return self._size

    @property
    def offsets(self) -> Dict[str, StackPointerOffset]:
        return self._offsets

    @property
    def accesses(self) -> List[Instruction]:
        return self._accesses

    @property
    def layout(self) -> Dict[int, StackAccess]:
        if len(self._layout) == 0:
            self._compute_layout()
        return self._layout

    @property
    def saved_registers(self) -> List[SavedRegister]:
        if len(self._saved_registers) == 0:
            self._compute_saved_registers()
        return list(self._saved_registers.values())

    def is_saved_register_slot(self, offset: int) -> bool:
        for r in self.saved_registers:
            if offset == r.offset:
                return True
        else:
            return False

    def stackbuffer(self, offset: int) -> Optional[StackBuffer]:
        if offset in self.layout:
            if self.is_saved_register_slot(offset):
                return StackBuffer(offset, lb=offset + 4, ub=offset + 4)
            else:
                for off in sorted(self.layout):
                    if off <= offset:
                        continue
                    lb = off
                    if self.is_saved_register_slot(off):
                        ub = off
                        return StackBuffer(offset, lb=lb, ub=ub)
                else:
                    return None
        else:
            return None

    def retrieve_saved_register(self, name: str, offset: int) -> SavedRegister:
        if (name, offset) in self._saved_registers:
            return self._saved_registers[(name, offset)]
        else:
            savedreg = SavedRegister(name, offset)
            self._saved_registers[(name, offset)] = savedreg
            return savedreg

    def retrieve_stack_access(
            self, offset: int, size: Optional[int] = None) -> StackAccess:
        if offset in self._layout:
            stackaccess = self._layout[offset]
            if size is not None:
                stackaccess.update_size(size)
        else:
            stackaccess = StackAccess(offset, size)
            self._layout[offset] = stackaccess
        return stackaccess

    def add_instr_offset(self, addr: str, offset: StackPointerOffset) -> None:
        self._offsets[addr] = offset

    def add_access(self, instr: Instruction) -> None:
        self._accesses.append(instr)
        self.add_instr_offset(instr.iaddr, instr.stackpointer_offset)

    def _compute_size(self) -> None:
        upperbounds: Dict[str, XBound] = {}
        lowerbounds: Dict[str, XBound] = {}
        singletons: Dict[str, int] = {}
        unknown: List[str] = []    # iaddr with open stackpointer interval
        for (iaddr, offset) in self.offsets.items():
            offrange = offset.offset
            if offrange.is_closed:
                if offrange.is_singleton:
                    singletons[iaddr] = offrange.lower_bound.bound.value
                else:
                    upperbounds[iaddr] = offrange.upper_bound
                    lowerbounds[iaddr] = offrange.lower_bound
            else:
                unknown.append(iaddr)

        if len(unknown) + len(upperbounds) + len(lowerbounds) == 0:
            # all stack offsets are known
            self._size = -(min(singletons[iaddr] for iaddr in singletons))

        else:
            self._size = -1

    def _compute_saved_registers(self) -> None:
        for instr in self.accesses:
            for mem in instr.memory_accesses:
                if mem.is_stack_address:
                    if mem.is_register_spill:
                        stackoffset = mem.address.stack_address_offset()
                        mem = cast(RegisterSpill, mem)
                        savedreg = self.retrieve_saved_register(
                            mem.register, stackoffset)
                        savedreg.add_spill(instr)
                    elif mem.is_register_restore:
                        stackoffset = mem.address.stack_address_offset()
                        mem = cast(RegisterRestore, mem)
                        savedreg = self.retrieve_saved_register(
                            mem.register, stackoffset)
                        savedreg.add_restore(instr)

    def _compute_layout(self) -> None:
        for instr in self.accesses:
            for access in instr.memory_accesses:
                if access.is_stack_address:
                    stackoffset = access.address.stack_address_offset()
                    stackaccess = self.retrieve_stack_access(
                        stackoffset, size=access.size)
                    if access.is_read:
                        stackaccess.add_read(instr)
                    if access.is_write:
                        stackaccess.add_write(instr)
            if instr.is_call_instruction:
                for arg in instr.call_arguments:
                    if arg.is_stack_address:
                        stackoffset = arg.stack_address_offset()
                        stackaccess = self.retrieve_stack_access(stackoffset)
                        stackaccess.add_escape(instr)

    def __str__(self) -> str:
        lines: List[str] = []
        if self.size == -1:
            lines.append("Stack size: unknown\n")
        else:
            lines.append("Stack size: " + str(self.size) + "\n")
        for instr in self.accesses:
            lines.append(str(instr))
        for savedreg in self.saved_registers:
            lines.append(str(savedreg))
        lines.append("-" * 80)
        for offset in sorted(self.layout, reverse=True):
            lines.append(str(self.layout[offset]))
        lines.append("-" * 80)
        return "\n".join(lines)
                
            
                

    

    
