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
"""CIL constant type.

Corresponds to constant in CIL

                                                          tags[0]  tags   args
type constant
    | CInt64                                               "int"     3      0
    | CStr                                                 "str"     1      1
    | CWStr                                                "wstr"    1+n    0
    | CChr                                                 "chr"     1      1
    | CReal                                                "real"    3      0
    | CEnum                                                "enum"    3      1
"""

from abc import ABC, abstractmethod
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


class BCConstant(BCDictionaryRecord, ABC):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def is_integer_constant(self) -> bool:
        return False

    def convert(self, converter: "BCConverter") -> AST.ASTConstant:
        raise NotImplementedError("BCCConstant.convert")

    def __str__(self) -> str:
        return "cil-constant:" + self.tags[0]


@bcregistry.register_tag("int", BCConstant)
class BCCInt64(BCConstant):
    """64-bit integer constant."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCConstant.__init__(self, bcd, ixval)

    @property
    def strvalue(self) -> str:
        return self.tags[1]

    @property
    def ikind(self) -> str:
        return self.tags[2]

    @property
    def value(self) -> int:
        return int(self.strvalue)

    @property
    def is_integer_constant(self) -> bool:
        return True

    def convert(self, converter: "BCConverter") -> AST.ASTIntegerConstant:
        return converter.convert_integer_constant(self)

    def __str__(self) -> str:
        return self.strvalue


@bcregistry.register_tag("str", BCConstant)
class BCStr(BCConstant):
    """Regular ASCII string."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCConstant.__init__(self, bcd, ixval)

    @property
    def strvalue(self) -> str:
        return self.bcd.string(self.args[0])

    @property
    def strlength(self) -> int:
        """Length without null-terminator in bytes."""

        return len(self.strvalue)

    def convert(self, converter: "BCConverter") -> AST.ASTStringConstant:
        return converter.convert_string_constant(self)

    def __str__(self) -> str:
        return self.strvalue


@bcregistry.register_tag("wstr", BCConstant)
class BCWStr(BCConstant):
    """Wide character string, specified as a list of integers."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCConstant.__init__(self, bcd, ixval)

    @property
    def wchars(self) -> List[int]:
        return [int(s) for s in self.tags[1:]]

    @property
    def strlength(self) -> int:
        """Number of characters (width unspecified)."""

        return len(self.wchars)

    def convert(self, converter: "BCConverter") -> AST.ASTConstant:
        raise NotImplementedError("BCWStr.convert")

    def __str__(self) -> str:
        return str(self.strlength) + "-char-wstr"


@bcregistry.register_tag("chr", BCConstant)
class BCChr(BCConstant):
    """Character specified by integer."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCConstant.__init__(self, bcd, ixval)

    @property
    def charvalue(self) -> int:
        return self.args[0]

    @property
    def charstr(self) -> str:
        return chr(self.charvalue)

    def convert(self, converter: "BCConverter") -> AST.ASTConstant:
        raise NotImplementedError("BCChr.convert")

    def __str__(self) -> str:
        return self.charstr


@bcregistry.register_tag("real", BCConstant)
class BCReal(BCConstant):
    """Floating point number specified by a string."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCConstant.__init__(self, bcd, ixval)

    @property
    def floatstr(self) -> str:
        return self.tags[1]

    @property
    def fkind(self) -> str:
        return self.tags[2]

    @property
    def floatvalue(self) -> float:
        return float(self.floatstr)

    def convert(self, converter: "BCConverter") -> AST.ASTConstant:
        raise NotImplementedError("BCReal.convert")

    def __str__(self) -> str:
        return self.floatstr


@bcregistry.register_tag("enum", BCConstant)
class BCEnum(BCConstant):
    """Enumeration value with name and value."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCConstant.__init__(self, bcd, ixval)

    @property
    def enumname(self) -> str:
        """Name of the enumeration type."""

        return self.tags[1]

    @property
    def enumvalname(self) -> str:
        """Name of the enumeration value."""

        return self.tags[2]

    @property
    def enumexp(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    def convert(self, converter: "BCConverter") -> AST.ASTConstant:
        raise NotImplementedError("BCEnum.convert")

    def __str__(self) -> str:
        return self.enumvalname
