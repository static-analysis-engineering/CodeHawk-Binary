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

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
import chb.app.ASTNode as AST

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
    def is_pointer(self) -> bool:
        return False

    @property
    def is_scalar(self) -> bool:
        return False

    @property
    def is_array(self) -> bool:
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

    def alignment(self) -> int:
        """Return alignment boundary in bytes."""
        return self.byte_size()

    def byte_size(self) -> int:
        """Return size in bytes."""
        return 0

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
    def is_scalar(self) -> bool:
        return True

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
    def is_scalar(self) -> bool:
        return True

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
    def size(self) -> Optional["BCExp"]:
        if self.args[1] == -1:
            return None
        else:
            return self.bcd.exp(self.args[1])

    @property
    def sizevalue(self) -> int:
        if self.has_constant_size():
            size = cast("BCExp", self.size)
            isize = cast("BCExpConst", size).constant
            return cast("BCCInt64", isize).value
        else:
            raise UF.CHBError("Array type does not have constant size")

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
        if self.size is not None:
            if self.size.is_constant:
                size = cast("BCExpConst", self.size)
                return size.is_integer_constant
        return False

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["args"] = [self.tgttyp.index]
        if self.has_constant_size():
            result["size"] = self.sizevalue
        return result

    def __str__(self) -> str:
        return str(self.tgttyp) + "[" + str(self.size) + "]"


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

    def byte_size(self) -> int:
        return self.typedef.ttype.byte_size()

    def serialize(self) -> Dict[str, Any]:
        result = BCTyp.serialize(self)
        result["name"] = self.tname
        return result

    def __str__(self) -> str:
        return self.tname


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
