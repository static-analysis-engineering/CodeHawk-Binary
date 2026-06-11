# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2026  Aarno Labs LLC
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


from typing import List, Optional, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import InterfaceDictionaryRecord

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.api.XXPredicate import XXPredicate


class FunctionQualifiers(InterfaceDictionaryRecord):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    def _optional_bool(self, index: int) -> Optional[bool]:
        r = self.args[index]
        if r == 2:
            return True
        elif r == 1:
            return False
        else:
            return None

    @property
    def fq_noreturn(self) -> Optional[bool]:
        return self._optional_bool(0)

    @property
    def fq_functional(self) -> Optional[str]:
        r = self.args[1]
        if r == 2:
            return "FConst"
        elif r == 1:
            return "FPure"
        else:
            return None

    @property
    def fq_sets_errno(self) -> Optional[bool]:
        return self._optional_bool(2)

    @property
    def fq_must_use_return(self) -> Optional[bool]:
        return self._optional_bool(3)

    def __str__(self) -> str:
        return (
            ("fq_noreturn: " + str(self.fq_noreturn) + "; "
             if self.fq_noreturn is not None else "")
            + ("fq_functional: " + str(self.fq_functional) + "; "
               if self.fq_functional is not None else "")
            + ("fq_sets_errno: " + str(self.fq_sets_errno) + "; "
               if self.fq_sets_errno is not None else "")
            + ("fq_must_use_return: " + str(self.fq_must_use_return) + ";"
               if self.fq_must_use_return is not None else ""))
