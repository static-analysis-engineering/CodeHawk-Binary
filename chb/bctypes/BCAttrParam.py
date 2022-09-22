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
"""CIL Attribute Parameter.

Corresponds to attrparam in CIL

                                                                 tags[0] tags args
type b_attrparam_t =                                            
| AInt of int                                                     "aint"   1   1                                     
| AStr of string                                                  "astr"   1   1
| ACons of string * b_attrparam_t list                            "acons"  2   n
| ASizeOf of btype_t                                            "asizeof"  1   1
| ASizeOfE of b_attrparam_t                                    "asizeofe"  1   1
| ASizeOfS of btypsig_t                                        "asizeofs"  1   1
| AAlignOf of btype_t                                          "aalignof"  1   1
| AAlignOfE of b_attrparam_t                                  "aalignofe"  1   1
| AAlignOfS of btypsig_t                                      "aalignofs"  1   1
| AUnOp of unop_t * b_attrparam_t                                 "aunop"  2   1
| ABinOp of binop_t * b_attrparam_t * b_attrparam_t              "abinop"  2   2 
| ADot of b_attrparam_t * string                                   "adot"  2   1
| AStar of b_attrparam_t                                          "astar"  1   1
| AAddrOf of b_attrparam_t                                      "aaddrof"  1   1
| AIndex of b_attrparam_t * b_attrparam_t                        "aindex"  1   2
| AQuestion of b_attrparam_t * b_attrparam_t * b_attrparam_t  "aquestion"  1   3

"""

from typing import List, TYPE_CHECKING

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord, bcregistry

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp
    from chb.bctypes.BCTypSig import BCTypSig


class BCAttrParam(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    def __str__(self) -> str:
        return "bc-attrparam:" + self.tags[0]


@bcregistry.register_tag("aint", BCAttrParam)
class BCAttrParamInt(BCAttrParam):
    """Integer value."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def intvalue(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return "aint(" + str(self.intvalue) + ")"


@bcregistry.register_tag("astr", BCAttrParam)
class BCAttrParamStr(BCAttrParam):
    """String value."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def strvalue(self) -> str:
        return self.bcd.string(self.args[0])

    def __str__(self) -> str:
        return "astr(" + self.strvalue + ")"


@bcregistry.register_tag("acons", BCAttrParam)
class BCAttrParamCons(BCAttrParam):
    """List of parameters."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def name(self) -> str:
        return self.tags[1]

    @property
    def params(self) -> List["BCAttrParam"]:
        return [self.bcd.attrparam(i) for i in self.args]

    def __str__(self) -> str:
        return (
            "acons("
            + self.name
            + "("
            + ", ".join(str(p) for p in self.params)
            + "))")


@bcregistry.register_tag("asizeof", BCAttrParam)
class BCAttrParamSizeOf(BCAttrParam):
    """Size of type."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    def __str__(self) -> str:
        return "asizeof(" + str(self.typ) + ")"


@bcregistry.register_tag("asizeofe", BCAttrParam)
class BCAttrParamSizeOfE(BCAttrParam):
    """Size of attribute parameter."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def param(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    def __str__(self) -> str:
        return "asizeofe(" + str(self.param) + ")"


@bcregistry.register_tag("asizeofs", BCAttrParam)
class BCAttrParamSizeOfS(BCAttrParam):
    """Size of a type signature."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def typsig(self) -> "BCTypSig":
        return self.bcd.typsig(self.args[0])

    def __str__(self) -> str:
        return "asizeofs(" + str(self.typsig) + ")"


@bcregistry.register_tag("aalignof", BCAttrParam)
class BCAttrParamAlignOf(BCAttrParam):
    """Alignment of type."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    def __str__(self) -> str:
        return "aalignof(" + str(self.typ) + ")"


@bcregistry.register_tag("aalignofe", BCAttrParam)
class BCAttrParamAlignOfE(BCAttrParam):
    """Alignment of attribute parameter."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)
    
    @property
    def param(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    def __str__(self) -> str:
        return "aalignofe(" + str(self.param) + ")"


@bcregistry.register_tag("aalignofs", BCAttrParam)
class BCAttrParamAlignOfS(BCAttrParam):
    """Alignment of type signature."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def typsig(self) -> "BCTypSig":
        return self.bcd.typsig(self.args[0])

    def __str__(self) -> str:
        return "aalignofs(" + str(self.typsig) + ")"


@bcregistry.register_tag("aunop", BCAttrParam)
class BCAttrParamUnOp(BCAttrParam):
    """Unary operation on parameter."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def operator(self) -> str:
        return self.tags[1]
    
    @property
    def param(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])
    
    def __str__(self) -> str:
        return "aunop(" + self.operator + ", " + str(self.param) + ")"


@bcregistry.register_tag("abinop", BCAttrParam)
class BCAttrParamBinOp(BCAttrParam):
    """Binary operation on parameters."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def operator(self) -> str:
        return self.tags[1]

    @property
    def param1(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    @property
    def param2(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[1])

    def __str__(self) -> str:
        return (
            "abinop("
            + self.operator
            + ", "
            + str(self.param1)
            + ", "
            + str(self.param2)
            + ")")


@bcregistry.register_tag("adot", BCAttrParam)
class BCAttrParamDot(BCAttrParam):
    """Parameter field."""

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def name(self) -> str:
        return self.tags[1]

    @property
    def param(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    def __str__(self) -> str:
        return "adot(" + self.name + ", " + str(self.param) + ")"


@bcregistry.register_tag("astar", BCAttrParam)
class BCAttrParamStar(BCAttrParam):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def param(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    def __str__(self) -> str:
        return "astar(" + str(self.param) + ")"


@bcregistry.register_tag("aadrof", BCAttrParam)
class BCAttrParamAddrOf(BCAttrParam):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def param(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    def __str__(self) -> str:
        return "aaddrof(" + str(self.param) + ")"


@bcregistry.register_tag("aindex", BCAttrParam)
class BCAttrParamIndex(BCAttrParam):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def param1(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    @property
    def param2(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[1])

    def __str__(self) -> str:
        return "aindex(" + str(self.param1) + ", " + str(self.param2) + ")"


@bcregistry.register_tag("aquestion", BCAttrParam)
class BCAttrParamQuestion(BCAttrParam):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCAttrParam.__init__(self, bcd, ixval)

    @property
    def param1(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[0])

    @property
    def param2(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[1])

    @property
    def param3(self) -> "BCAttrParam":
        return self.bcd.attrparam(self.args[2])

    def __str__(self) -> str:
        return (
            "aquestion("
            + str(self.param1)
            + ", "
            + str(self.param2)
            + ", "
            + str(self.param3)
            + ")")
