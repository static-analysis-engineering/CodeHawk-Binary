# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Compares two instructions in two related functions in different binaries."""

from typing import cast, Optional, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.Instruction import Instruction


class InstructionRelationalAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            i1: "Instruction",
            app2: "AppAccess",
            i2: Optional["Instruction"]) -> None:
        self._app1 = app1
        self._app2 = app2
        self._instr1 = i1
        self._instr2 = i2

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def instr1(self) -> "Instruction":
        return self._instr1

    @property
    def instr2(self) -> "Instruction":
        if self.is_mapped:
            return cast("Instruction", self._instr2)
        else:
            raise UF.CHBError(
                "No corresponding instruction found for " + self.instr1.iaddr)

    @property
    def is_mapped(self) -> bool:
        return self._instr2 is not None

    @property
    def same_endianness(self) -> bool:
        return self.app1.header.is_big_endian == self.app2.header.is_big_endian

    @property
    def is_md5_equal(self) -> bool:
        if self.is_mapped:
            if self.same_endianness:
                return self.instr1.md5() == self.instr2.md5()
            else:
                return self.instr1.md5() == self.instr2.rev_md5()
        else:
            return False

    @property
    def loads_same_string(self) -> bool:
        s1 = self.instr1.string_pointer_loaded()
        if s1:
            s2 = self.instr2.string_pointer_loaded()
            if s2:
                return (s1[0] == s2[0] and s1[1] == s2[1])
            else:
                return False
        else:
            return False

    @property
    def calls_same_function_with_same_args(self) -> bool:
        return False

    @property
    def is_semantically_equal(self) -> bool:
        """Return true if the action taken is equivalent."""

        return (
            self.loads_same_string
            or self.calls_same_function_with_same_args)
