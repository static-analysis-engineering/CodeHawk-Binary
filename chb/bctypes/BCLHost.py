# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
"""CIL LHost value

Corresponds to lhost in CIL

                                                          tags[0]  tags   args
type lhost
  | Var                                                    "var"     2      1
  | Mem                                                    "mem"     1      1
"""

from typing import List, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.bctypes.BCConverter import BCConverter
from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord, bcregistry
from chb.bctypes.BCVisitor import BCVisitor

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCExp import BCExp


class BCLHost(BCDictionaryRecord):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, cd, ixval)

    def convert(self, converter: "BCConverter") -> AST.ASTLHost:
        raise NotImplementedError("BCLHost.convert")

    def __str__(self) -> str:
        return "bc-lhost:" + self.tags[0]


@bcregistry.register_tag("var", BCLHost)
class BCHostVar(BCLHost):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCLHost.__init__(self, cd, ixval)

    @property
    def varname(self) -> str:
        return self.tags[1]

    @property
    def varvid(self) -> int:
        return self.args[0]

    def accept(self, visitor: "BCVisitor") -> None:
        return visitor.visit_variable(self)

    def convert(self, converter: "BCConverter") -> AST.ASTVariable:
        return converter.convert_variable(self)

    def __str__(self) -> str:
        return self.varname


@bcregistry.register_tag("mem", BCLHost)
class BCHostMem(BCLHost):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCLHost.__init__(self, cd, ixval)

    @property
    def memexp(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    def accept(self, visitor: "BCVisitor") -> None:
        return visitor.visit_memref(self)

    def convert(self, converter: "BCConverter") -> AST.ASTMemRef:
        return converter.convert_memref(self)

    def __str__(self) -> str:
        return "*" + str(self.memexp)
