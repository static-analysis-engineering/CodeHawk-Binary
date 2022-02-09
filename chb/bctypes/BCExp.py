# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
"""CIL expression.

Corresponds to exp in CIL

                                                          tags[0]  tags   args
type exp
    | Const                                               "const"    1      1
    | Lval                                                "lval"     1      1
    | SizeOf                                              "sizeof"   1      1
    | SizeOfE                                             "sizeofe"  1      1
    | SizeOfStr                                          "sizeofstr" 1      1
    | AlignOf                                             "alignof"  1      1
    | AlignOfE                                            "alignofe" 1      1
    | UnOp                                                  "unop"   2      2
    | BinOp                                                 "binop"  2      3
    | Question                                            "question" 1      4
    | CastE                                                 "caste"  1      2
    | AddrOf                                                "addrof" 1      1
    | AddrOfLabel                                      "addroflabel" 1      1
    | StartOf                                              "startof" 1      1

"""

from typing import List, TYPE_CHECKING

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord, bcregistry

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCConstant import BCConstant
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCLval import BCLval
    from chb.bctypes.BCTyp import BCTyp


class BCExp(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def is_constant(self) -> bool:
        return False

    @property
    def is_integer_constant(self) -> bool:
        return False

    def __str__(self) -> str:
        return "bc-exp:" + self.tags[0]


@bcregistry.register_tag("const", BCExp)
class BCExpConst(BCExp):
    """Constant value."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def constant(self) -> "BCConstant":
        return self.bcd.constant(self.args[0])

    @property
    def is_constant(self) -> bool:
        return True

    @property
    def is_integer_constant(self) -> bool:
        return self.constant.is_integer_constant

    def __str__(self) -> str:
        return str(self.constant)


@bcregistry.register_tag("lval", BCExp)
class BCExpLval(BCExp):
    """Right-hand side l-value."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def lval(self) -> "BCLval":
        return self.bcd.lval(self.args[0])

    def __str__(self) -> str:
        return "lval(" + str(self.lval) + ")"


@bcregistry.register_tag("sizeof", BCExp)
class BCExpSizeOf(BCExp):
    """Size-of type construct."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    def __str__(self) -> str:
        return "sizeof(" + str(self.typ) + ")"


@bcregistry.register_tag("sizeofe", BCExp)
class BCExpSizeOfE(BCExp):
    """Size-of (type of) expression construct."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def exp(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    def __str__(self) -> str:
        return "sizeof(" + str(self.exp) + ")"


@bcregistry.register_tag("sizeofstr", BCExp)
class BCExpSizeOfStr(BCExp):
    """Size of a string."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def strvalue(self) -> str:
        return self.bcd.string(self.args[0])

    def __str__(self) -> str:
        return "sizeof(" + self.strvalue + ")"


@bcregistry.register_tag("alignof", BCExp)
class BCExpAlignOf(BCExp):
    """Align of a type."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    def __str__(self) -> str:
        return "alignof(" + str(self.typ) + ")"


@bcregistry.register_tag("alignofe", BCExp)
class BCExpAlignOfE(BCExp):
    """Align of (the type of) an expression."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def exp(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    def __str__(self) -> str:
        return "alignof(" + str(self.exp) + ")"


@bcregistry.register_tag("unop", BCExp)
class BCExpUnOp(BCExp):
    """Unary operation."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def operator(self) -> str:
        return self.tags[1]

    @property
    def exp(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[1])

    def __str__(self) -> str:
        return self.operator + str(self.exp)


@bcregistry.register_tag("binop", BCExp)
class BCExpBinOp(BCExp):
    """Binary operation."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def operator(self) -> str:
        return self.tags[1]

    @property
    def exp1(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    @property
    def exp2(self) -> "BCExp":
        return self.bcd.exp(self.args[1])

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[2])

    def __str__(self) -> str:
        return str(self.exp1) + " " + self.operator + " " + str(self.exp2)


@bcregistry.register_tag("question", BCExp)
class BCExpQuestion(BCExp):
    """Question expression construct ..?..:.. ."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def exp1(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    @property
    def exp2(self) -> "BCExp":
        return self.bcd.exp(self.args[1])

    @property
    def exp3(self) -> "BCExp":
        return self.bcd.exp(self.args[2])

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[3])

    def __str__(self) -> str:
        return (
            str(self.exp1)
            + " ? "
            + str(self.exp2)
            + " : "
            + str(self.exp3))


@bcregistry.register_tag("caste", BCExp)
class BCExpCastE(BCExp):
    """Cast expression."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def exp(self) -> "BCExp":
        return self.bcd.exp(self.args[1])

    def __str__(self) -> str:
        return "(" + str(self.typ) + ")" + str(self.exp)


@bcregistry.register_tag("addrof", BCExp)
class BCExpAddressOf(BCExp):
    """Address-of construct."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def lval(self) -> "BCLval":
        return self.bcd.lval(self.args[0])

    def __str__(self) -> str:
        return "&" + str(self.lval)


@bcregistry.register_tag("addroflabel", BCExp)
class BCExpAddressOfLabel(BCExp):
    """Address of a statement reference."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def stmtid(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return "stmt-" + str(self.stmtid)


@bcregistry.register_tag("startof", BCExp)
class BCExpStartOf(BCExp):
    """Same as address-of, but mostly applied to arrays."""

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCExp.__init__(self, cd, ixval)

    @property
    def lval(self) -> "BCLval":
        return self.bcd.lval(self.args[0])

    def __str__(self) -> str:
        return "&" + str(self.lval)
