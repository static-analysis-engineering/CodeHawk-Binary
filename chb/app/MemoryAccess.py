# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs LLC
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
"""Represents an instruction's access to memory."""

from typing import Optional

from chb.bctypes.BCTyp import BCTyp
from chb.invariants.XXpr import XXpr


class MemoryAccess:

    def __init__(
            self,
            memaddr: XXpr,
            mode: str,               # R/W/RW
            size: Optional[int] = None,    # size in bytes
            memtype: Optional[BCTyp] = None) -> None:
        self._memaddr = memaddr
        self._mode = mode
        self._size = size
        self._memtype = memtype

    @property
    def address(self) -> XXpr:
        return self._memaddr

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def is_read(self) -> bool:
        return self.mode in ["R", "RW"]

    @property
    def is_write(self) -> bool:
        return self.mode in ["W", "RW"]

    @property
    def is_read_write(self) -> bool:
        return self.mode == "RW"

    @property
    def size(self) -> Optional[int]:
        return self._size

    @property
    def memtype(self) -> Optional[BCTyp]:
        return self._memtype

    @property
    def is_register_spill(self) -> bool:
        return False

    @property
    def is_register_restore(self) -> bool:
        return False

    @property
    def is_stack_address(self) -> bool:
        return self.address.is_stack_address

    def __str__(self) -> str:
        ptype = str(self.memtype) if self.memtype is not None else ""
        psize = " (" + str(self.size) + ") " if self.size is not None else ""
        return ptype + psize + str(self.address)


class RegisterSpill(MemoryAccess):

    def __init__(self, memaddr: XXpr, register: str) -> None:
        MemoryAccess.__init__(self, memaddr, "W", size=4)
        self._register = register

    @property
    def register(self) -> str:
        return self._register

    @property
    def is_register_spill(self) -> bool:
        return True

    def __str__(self) -> str:
        return (MemoryAccess.__str__(self) + "  " + self.register + " saved")


class RegisterRestore(MemoryAccess):

    def __init__(self, memaddr: XXpr, register: str) -> None:
        MemoryAccess.__init__(self, memaddr, "R", size=4)
        self._register = register

    @property
    def register(self) -> str:
        return self._register

    @property
    def is_register_restore(self) -> bool:
        return True

    def __str__(self) -> str:
        return (MemoryAccess.__str__(self) + "  " + self.register + " restored")
