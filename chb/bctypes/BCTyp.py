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
"""CIL type typ.

Corresponds to typ in CIL

                                                          tags[0]  tags   args
type typ
    | TVoid                                               "tvoid"    1      0
    | TInt                                                "tint"     2      0
    | TFloat                                              "tfloat"   2      0
    | TPtr                                                "tptr"     1      1
    | TArray                                              "tarray"   1      2
    | TFun                                                "tfun"     1      3
    | TNamed                                              "tnamed"   2      0
    | TComp                                               "tcomp"    1      1
    | TEnum                                               "tenum"    2      0
    | TBuiltin_va_list                           "tbuiltin-va-list"  1      0

Note: each type potentially also has a variable number of attributes added onto
the args.
"""

from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord, bcregistry

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCConstant import BCCInt64
    from chb.bctypes.BCCompInfo import BCCompInfo
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCExp import BCExp, BCExpConst
    from chb.bctypes.BCFunArgs import BCFunArgs
    from chb.bctypes.BCTypeInfo import BCTypeInfo


inttypes = {
    "ichar": "char",
    "ischar": "signed char",
    "iuchar": "unsigned char",
    "ibool": "bool",
    "iint": "int",
    "iuint": "unsigned int",
    "ishort": "short",
    "iushort": "unsigned short",
    "ilong": "long",
    "iulong": "unsigned long",
    "ilonglong": "long long",
    "iulonglong": "unsigned long long"
}


floattypes = {
    "float": "float",
    "fdouble": "double",
    "flongdouble": "long double"
}


intsizes = {
    "ichar": 1,
    "ischar": 1,
    "iuchar": 1,
    "ibool": 1,
    "iint": 4,
    "iuint": 4,
    "ishort": 2,
    "iushort": 2,
    "ilong": 4,
    "iulong": 4,
    "ilonglong": 8,
    "iulonglong": 8
}


floatsizes = {
    "float": 4,
    "fdouble": 8,
    "flongdouble": 8    # ??
}


def size_of_integer_type(ikind: str) -> int:
    if ikind in intsizes:
        return intsizes[ikind]
    else:
        raise UF.CHBError("Integer type not recognized: " + ikind)


def size_of_float_type(fkind: str) -> int:
    if fkind in floatsizes:
        return floatsizes[fkind]
    else:
        raise UF.CHBError("Float type not recognized: " + fkind)


class BCTyp(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def is_void(self) -> bool:
        return False

    @property
    def is_integer(self) -> bool:
        return False

    @property
    def is_float(self) -> bool:
        return False

    @property
    def is_pointer(self) -> bool:
        return False

    @property
    def is_scalar(self) -> bool:
        return False

    @property
    def is_array(self) -> bool:
        return False

    def has_constant_size(self) -> bool:
        return False

    @property
    def is_struct(self) -> bool:
        return False

    @property
    def is_union(self) -> bool:
        return False

    @property
    def is_function(self) -> bool:
        return False

    @property
    def is_vararg(self) -> bool:
        return False

    def is_leq(self, other: "BCTyp") -> bool:
        """Return true if this type is more precise or equal."""

        return False

    def alignment(self) -> int:
        """Return alignment boundary in bytes."""
        return self.byte_size()

    def byte_size(self) -> int:
        """Return size in bytes."""
        return 0

    @property
    def ikind(self) -> str:
        raise UF.CHBError("Type is not an integer: " + str(self))

    @property
    def fkind(self) -> str:
        raise UF.CHBError("Type is not a float: " + str(self))

    @property
    def tgttyp(self) -> "BCTyp":
        raise UF.CHBError("Type does not have a target type: " + str(self))

    @property
    def size_expr(self) -> Optional["BCExp"]:
        raise UF.CHBError("Type does not have a size expression: " + str(self))

    @property
    def sizevalue(self) -> int:
        raise UF.CHBError("Type does not have a size value: " + str(self))

    @property
    def returntype(self) -> "BCTyp":
        raise UF.CHBError("Type does not have a return type: " + str(self))

    @property
    def argtypes(self) -> Optional["BCFunArgs"]:
        raise UF.CHBError("Type is not a function: " + str(self))

    def serialize(self) -> Dict[str, Any]:
        result = BCDictionaryRecord.serialize(self)
        result["tag"] = self.tags[0]
        return result

    def __str__(self) -> str:
        return "cil-typ:" + self.tags[0]


@bcregistry.register_tag("tvoid", BCTyp)
class BCTypVoid(BCTyp):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, bcd, ixval)

    @property
    def is_void(self) -> bool:
        return True

    def is_leq(self, other: "BCTyp") -> bool:
        return other.is_void

    def serialize(self) -> Dict[str, Any]:
        return BCTyp.serialize(self)

    def __str__(self) -> str:
        return "void"


@bcregistry.register_tag("tint", BCTyp)
class BCTypInt(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def ikind(self) -> str:
        return self.tags[1]

    @property
    def is_integer(self) -> bool:
        return True

    @property
    def is_scalar(self) -> bool:
        return True

    def is_leq(self, other: "BCTyp") -> bool:
        if other.is_integer:
            other = cast("BCTypInt", other)
            return other.ikind == self.ikind
        else:
            return False

    def byte_size(self) -> int:
        return size_of_integer_type(self.ikind)

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["ikind"] = self.ikind
        return result

    def __str__(self) -> str:
        return inttypes[self.ikind]


@bcregistry.register_tag("tfloat", BCTyp)
class BCTypFloat(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def fkind(self) -> str:
        return self.tags[1]

    @property
    def is_float(self) -> bool:
        return True

    @property
    def is_scalar(self) -> bool:
        return True

    def is_leq(self, other: "BCTyp") -> bool:
        if other.is_float:
            other = cast("BCTypFloat", other)
            return other.fkind == self.fkind
        else:
            return False

    def byte_size(self) -> int:
        return size_of_float_type(self.fkind)

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["fkind"] = self.fkind
        return result

    def __str__(self) -> str:
        return floattypes[self.fkind]


@bcregistry.register_tag("tptr", BCTyp)
class BCTypPtr(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def tgttyp(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def is_pointer(self) -> bool:
        return True

    @property
    def is_scalar(self) -> bool:
        return True

    def is_leq(self, other) -> bool:
        if other.is_pointer:
            other = cast("BCTypPtr", other)
            return (
                other.tgttyp.is_void or other.tgttyp.is_leq(self.tgttyp))
        else:
            return False

    def byte_size(self) -> int:
        """We assume 32-bit systems."""

        return 4

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["args"] = self.tgttyp.index
        return result

    def __str__(self) -> str:
        return str(self.tgttyp) + " *"


@bcregistry.register_tag("tarray", BCTyp)
class BCTypArray(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def tgttyp(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def size_expr(self) -> Optional["BCExp"]:
        if self.args[1] == -1:
            return None
        else:
            return self.bcd.exp(self.args[1])

    @property
    def sizevalue(self) -> int:
        if self.has_constant_size():
            size = cast("BCExp", self.size_expr)
            isize = cast("BCExpConst", size).constant
            return cast("BCCInt64", isize).value
        else:
            raise UF.CHBError("Array type does not have constant size")

    def is_leq(self, other: "BCTyp") -> bool:
        if other.is_array:
            other = cast("BCTypArray", other)
            if other.has_constant_size() and self.has_constant_size():
                return (
                    other.sizevalue == self.sizevalue
                    and other.tgttyp.is_leq(self.tgttyp))
            elif self.has_constant_size():
                return (
                    other.tgttyp.is_leq(self.tgttyp))
            else:
                return False
        else:
            return False

    # Alignment is ignored
    def byte_size(self) -> int:
        if self.has_constant_size():
            elts = self.sizevalue
            return elts * self.tgttyp.byte_size()
        else:
            return 4

    def alignment(self) -> int:
        return self.tgttyp.alignment()

    @property
    def is_array(self) -> bool:
        return True

    def has_constant_size(self) -> bool:
        if self.size_expr is not None:
            if self.size_expr.is_constant:
                size = cast("BCExpConst", self.size_expr)
                return size.is_integer_constant
        return False

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["args"] = [self.tgttyp.index]
        if self.has_constant_size():
            result["size"] = self.sizevalue
        return result

    def __str__(self) -> str:
        return str(self.tgttyp) + "[" + str(self.size_expr) + "]"


@bcregistry.register_tag("tfun", BCTyp)
class BCTypFun(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def returntype(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def argtypes(self) -> Optional["BCFunArgs"]:
        if self.args[1] == -1:
            return None
        else:
            return self.bcd.funargs(self.args[1])

    @property
    def is_vararg(self) -> bool:
        return self.args[2] == 1

    @property
    def is_function(self) -> bool:
        return True

    def is_leq(self, other: "BCTyp") -> bool:
        if other.is_function:
            other = cast("BCTypFun", other)
            if self.returntype.is_leq(other.returntype):
                if self.argtypes and other.argtypes:
                    return self.argtypes.is_leq(other.argtypes)
                elif self.argtypes:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["args"] = [self.returntype.index]
        if self.argtypes is not None:
            argtypes = [t.index for t in self.argtypes.argtypes]
            result["args"].extend(argtypes)
        return result

    def __str__(self) -> str:
        return str(self.returntype) + "__" + str(self.argtypes)


@bcregistry.register_tag("tnamed", BCTyp)
class BCTypNamed(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def tname(self) -> str:
        return self.tags[1]

    @property
    def typedef(self) -> "BCTypeInfo":
        return self.bcd.typeinfo_by_name(self.tname)

    @property
    def is_scalar(self) -> bool:
        return self.typedef.ttype.is_scalar

    @property
    def is_integer(self) -> bool:
        return self.typedef.ttype.is_integer

    @property
    def is_float(self) -> bool:
        return self.typedef.ttype.is_float

    @property
    def is_pointer(self) -> bool:
        return self.typedef.ttype.is_pointer

    @property
    def is_array(self) -> bool:
        return self.typedef.ttype.is_array

    def has_constant_size(self) -> bool:
        return self.typedef.ttype.has_constant_size()

    @property
    def is_function(self) -> bool:
        return self.typedef.ttype.is_function

    @property
    def is_vararg(self) -> bool:
        return self.typedef.ttype.is_vararg

    @property
    def ikind(self) -> str:
        return self.typedef.ttype.ikind

    @property
    def fkind(self) -> str:
        return self.typedef.ttype.fkind

    @property
    def tgttyp(self) -> "BCTyp":
        return self.typedef.ttype.tgttyp

    @property
    def size_expr(self) -> Optional["BCExp"]:
        return self.typedef.ttype.size_expr

    @property
    def sizevalue(self) -> int:
        return self.typedef.ttype.sizevalue

    @property
    def returntype(self) -> "BCTyp":
        return self.typedef.ttype.returntype

    @property
    def argtypes(self) -> Optional["BCFunArgs"]:
        return self.typedef.ttype.argtypes

    def is_leq(self, other: "BCTyp") -> bool:
        return self.typedef.ttype.is_leq(other)

    def byte_size(self) -> int:
        return self.typedef.ttype.byte_size()

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["name"] = self.tname
        return result

    def __str__(self) -> str:
        return str(self.typedef.ttype)
        # return self.tname + " (" + str(self.typedef.ttype) + ")"


@bcregistry.register_tag("tcomp", BCTyp)
class BCTypComp(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def compkey(self) -> int:
        return self.args[0]

    @property
    def compinfo(self) -> "BCCompInfo":
        return self.bcd.compinfo_by_key(self.compkey)

    @property
    def compname(self) -> str:
        return self.compinfo.cname

    @property
    def is_struct(self) -> bool:
        return self.compinfo.is_struct

    @property
    def is_union(self) -> bool:
        return self.compinfo.is_union

    def is_leq(self, other: "BCTyp"):
        if other.is_struct:
            other = cast("BCTypComp", other)
            return self.compinfo.is_leq(other.compinfo)
        else:
            return False

    def byte_size(self) -> int:
        return self.compinfo.byte_size()

    def alignment(self) -> int:
        return self.compinfo.alignment()

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["key"] = self.compkey
        return result

    def __str__(self) -> str:
        return "struct " + self.compname


@bcregistry.register_tag("tenum", BCTyp)
class BCTypEnum(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    @property
    def ename(self) -> str:
        return self.tags[1]

    @property
    def is_scalar(self) -> bool:
        return True

    def byte_size(self) -> int:
        return 4

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["name"] = self.ename
        return result

    def __str__(self) -> str:
        return self.ename


@bcregistry.register_tag("tbuiltin-va-list", BCTyp)
class BCTypBuiltinVaList(BCTyp):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTyp.__init__(self, cd, ixval)

    def __str__(self) -> str:
        return "builtin-va-list"
