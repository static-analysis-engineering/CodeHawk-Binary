# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
"""ARM extension registers used for vectors and floating point values."""

from typing import TYPE_CHECKING

from chb.app.BDictionaryRecord import BDictionaryRecord

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary


class ARMExtensionRegister(BDictionaryRecord):

    def __init__(
            self,
            bd: "BDictionary",
            ixval: IndexedTableValue) -> None:
        BDictionaryRecord.__init__(self, bd, ixval)

    @property
    def regtype(self) -> str:
        return self.tags[0]

    @property
    def regindex(self) -> int:
        return self.args[0]

    @property
    def is_single(self) -> bool:
        return self.regtype == "S"

    @property
    def is_double(self) -> bool:
        return self.regtype == "D"

    @property
    def is_quad(self) -> bool:
        return self.regtype == "Q"

    def __str__(self) -> str:
        return self.regtype + str(self.regindex)


class ARMExtensionRegisterElement(BDictionaryRecord):

    def __init__(
            self,
            bd: "BDictionary",
            ixval: IndexedTableValue) -> None:
        BDictionaryRecord.__init__(self, bd, ixval)

    @property
    def xregister(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    @property
    def element_index(self) -> int:
        return self.args[1]

    @property
    def element_size(self) -> int:
        return self.args[2]

    def __str__(self) -> str:
        return str(self.xregister) + "[" + str(self.element_index) + "]"


class ARMExtensionRegisterReplicatedElement(BDictionaryRecord):

    def __init__(
            self,
            bd: "BDictionary",
            ixval: IndexedTableValue) -> None:
        BDictionaryRecord.__init__(self, bd, ixval)

    @property
    def xregister(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    @property
    def element_size(self) -> int:
        return self.args[1]

    @property
    def element_count(self) -> int:
        return self.args[2]

    def __str__(self) -> str:
        return str(self.xregister) + "[]"
