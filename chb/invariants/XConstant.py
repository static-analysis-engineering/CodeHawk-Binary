# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
"""Constant value

Represents xcst_t in xprlib/xprTypes:

                                tags[0]    tags   args
type xcst_t =
  | SymSet of symbol_t list      "ss"       1     list length
  | IntConst of numerical_t      "ic"       1       1
  | BoolConst of bool            "bc"       1       1
  | XRandom                      "r"        1       0
  | XUnknownInt                  "ui"       1       0
  | XUnknownSet                  "us"       1       0

"""

from typing import Any, Dict, List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnXprDictionaryRecord, xprregistry
from chb.invariants.XNumerical import XNumerical
from chb.invariants.XSymbol import XSymbol

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.invariants.FnXprDictionary


class XConstant(FnXprDictionaryRecord):
    """Base class of constant values."""

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        FnXprDictionaryRecord.__init__(self, xd, ixval)

    @property
    def is_string_reference(self) -> bool:
        return False

    def string_reference(self) -> str:
        raise UF.CHBError("Constant " + str(self) + " is not a string reference")

    @property
    def is_global_address(self) -> bool:
        return False

    @property
    def is_symset(self) -> bool:
        return False

    @property
    def is_intconst(self) -> bool:
        return False

    @property
    def is_boolconst(self) -> bool:
        return False

    @property
    def is_random(self) -> bool:
        return False

    @property
    def is_unknown_int(self) -> bool:
        return False

    @property
    def is_unknown_set(self) -> bool:
        return False

    @property
    def is_int_constant(self) -> bool:
        return False

    @property
    def constant(self) -> XNumerical:
        raise UF.CHBError("Constant not supported by " + str(self))

    @property
    def value(self) -> int:
        raise UF.CHBError("Value not supported by " + str(self))

    def to_json_result(self) -> JSONResult:
        return JSONResult(
            "xconstant",
            {},
            "fail",
            "xconstant: not yet implemented (" + self.tags[0] + ")")

    def __str__(self) -> str:
        return 'basexcst:' + self.tags[0]


@xprregistry.register_tag("ss", XConstant)
class XSymSet(XConstant):

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XConstant.__init__(self, xd, ixval)

    @property
    def is_symset(self) -> bool:
        return True

    def symbols(self) -> List[XSymbol]:
        return [self.xd.symbol(i) for i in self.args]

    def __str__(self) -> str:
        return '[' + ','.join([str(x) for x in self.symbols()]) + ']'


@xprregistry.register_tag("ic", XConstant)
class XIntConst(XConstant):
    """Integer constant.

    args[0]: index in xd to numerical value
    """

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XConstant.__init__(self, xd, ixval)

    @property
    def constant(self) -> XNumerical:
        return self.xd.numerical(self.args[0])

    @property
    def value(self) -> int:
        return self.constant.value

    @property
    def is_global_address(self) -> bool:
        return self.app.header.is_in_address_space(self.value)

    @property
    def is_int_constant(self) -> bool:
        return True

    @property
    def is_string_reference(self) -> bool:
        return self.vd.stringsxrefs.has_string(str(hex(self.value)))

    def string_reference(self) -> str:
        return self.vd.stringsxrefs.string(str(hex(self.value)))

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["value"] = self.value
        if self.is_string_reference:
            content["stringref"] = self.string_reference()
        content["txtrep"] = str(self)
        return JSONResult("xconstant", content, "ok")

    def __str__(self) -> str:
        if (
                self.is_string_reference
                and len(self.string_reference()) > 1):
            return '"' + self.string_reference() + '"'
        elif self.value > 1000:
            return str(hex(self.value))
        else:
            return str(self.constant)


@xprregistry.register_tag("bc", XConstant)
class XBoolConst(XConstant):
    """Boolean constant value.

    args[0]: 1 if true, 0 if false
    """

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XConstant.__init__(self, xd, ixval)

    @property
    def is_boolconst(self) -> bool:
        return True

    @property
    def is_true(self) -> bool:
        return self.args[0] == 1

    @property
    def is_false(self) -> bool:
        return self.args[0] == 0

    def __str__(self) -> str:
        return "true" if self.is_true else 'false'


@xprregistry.register_tag("r", XConstant)
class XRandom(XConstant):
    """Constant value with unknonwn value."""

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XConstant.__init__(self, xd, ixval)

    @property
    def is_random(self) -> bool:
        return True

    def __str__(self) -> str:
        return "??"


@xprregistry.register_tag("ui", XConstant)
class XUnknownInt(XConstant):
    """Integer constant with unknown value."""

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XConstant.__init__(self, xd, ixval)

    @property
    def is_unknown_int(self) -> bool:
        return True

    def __str__(self) -> str:
        return "unknown int"


@xprregistry.register_tag("us", XConstant)
class BXUnknownSet(XConstant):

    def __init__(
            self,
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XConstant.__init__(self, xd, ixval)

    @property
    def is_unknown_set(self) -> bool:
        return True

    def __str__(self) -> str:
        return "unknown set"
