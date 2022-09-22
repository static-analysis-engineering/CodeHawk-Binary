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
""" CIL Type Signature Attribute.

Corresponds to typsig in CIL
                                                                          tags[0]
and btypsig_t =
| TSArray of btypsig_t * int64 option * b_attribute_t list               "tsarray"
| TSPtr of btypsig_t * b_attribute_t list                                "tsptr"
| TSComp of bool * string * b_attribute_t list                           "tscomp"
| TSFun of btypsig_t * btypsig_t list option * bool * b_attribute_t list  "tsfun"
| TSEnum of string * b_attribute_t list                                  "tsenum"
| TSBase of btype_t                                                      "tsbase"

"""

from typing import List, Optional, TYPE_CHECKING

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord, bcregistry

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCAttribute import BCAttribute, BCAttributes
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp


class BCTypSig(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    def get_attrs(self, index: int) -> List["BCAttribute"]:
        if len(self.args) > index:
            return self.bcd.attributes(self.args[index]).attrs
        else:
            return []

    def attrs_str(self, attrs: List["BCAttribute"]) -> str:
        if len(attrs) == 0:
            return ""
        else:
            return "[" + ", ".join(str(a) for a in attrs) + "]"

    def __str__(self) -> str:
        return "typsig:" + self.tags[0]


@bcregistry.register_tag("tsarray", BCTypSig)
class BCTSArray(BCTypSig):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTypSig.__init__(self, bcd, ixval)

    @property
    def size(self) -> Optional[int]:
        if len(self.tags) > 1:
            return int(self.tags[1])
        else:
            return None

    @property
    def elementtypsig(self) -> "BCTypSig":
        return self.bcd.typsig(self.args[0])

    @property
    def attrs(self) -> List["BCAttribute"]:
        return self.get_attrs(1)

    def __str__(self) -> str:
        size = "?" if self.size is None else str(self.size)
        return (
            "tsarray("
            + str(self.elementtypsig)
            + ", "
            + size
            + ")"
            + self.attrs_str(self.attrs))


@bcregistry.register_tag("tsptr", BCTypSig)
class BCTSPtr(BCTypSig):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTypSig.__init__(self, bcd, ixval)

    @property
    def targettypsig(self) -> "BCTypSig":
        return self.bcd.typsig(self.args[0])

    @property
    def attrs(self) -> List["BCAttribute"]:
        return self.get_attrs(1)

    def __str__(self) -> str:
        return (
            "tsptr("
            + str(self.targettypsig)
            + ")"
            + self.attrs_str(self.attrs))


@bcregistry.register_tag("tscomp", BCTypSig)
class BCTSComp(BCTypSig):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTypSig.__init__(self, bcd, ixval)

    @property
    def name(self) -> str:
        return self.tags[1]

    @property
    def is_struct(self) -> bool:      # TBD: confirm meaning
        return self.args[0] == 1

    @property
    def attrs(self) -> List["BCAttribute"]:
        return self.get_attrs(1)

    def __str__(self) -> str:
        return (
            "tscomp("
            + self.name
            + ", "
            + str(self.is_struct)
            + ")"
            + self.attrs_str(self.attrs))


@bcregistry.register_tag("tsfun", BCTypSig)
class BCTSFun(BCTypSig):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTypSig.__init__(self, bcd, ixval)

    @property
    def returntypsig(self) -> "BCTypSig":
        return self.bcd.typsig(self.args[0])

    @property
    def argtypsigs(self) -> Optional[List["BCTypSig"]]:
        typsiglist = self.bcd.optional_typsig_list(self.args[1])
        if typsiglist is None:
            return None
        else:
            return typsiglist.typsigs

    @property
    def attrs(self) -> List["BCAttribute"]:
        return self.get_attrs(3)

    def __str__(self) -> str:
        args = (
            "?"
            if self.argtypsigs is None
            else ", ".join(str(t) for t in self.argtypsigs))
        return (
            "tsfun"
            + str(self.returntypsig)
            + ", "
            + args
            + ")"
            + self.attrs_str(self.attrs))


@bcregistry.register_tag("tsenum", BCTypSig)
class BCTSEnum(BCTypSig):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTypSig.__init__(self, bcd, ixval)

    @property
    def name(self) -> str:
        return self.tags[1]

    @property
    def attrs(self) -> List["BCAttribute"]:
        return self.get_attrs(0)

    def __str_(self) -> str:
        return "tsenum(" + self.name + ")" + self.attrs_str(self.attrs)


@bcregistry.register_tag("tsbase", BCTypSig)
class BCTSBase(BCTypSig):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCTypSig.__init__(self, bcd, ixval)

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    def __str__(self) -> str:
        return "tsbase(" + str(self.typ) + ")"
                            

class BCTypSigList(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def typsigs(self) -> List["BCTypSig"]:
        return [self.bcd.typsig(i) for i in self.args]

    def __str__(self) -> str:
        return ", ".join(str(t) for t in self.typsigs)
