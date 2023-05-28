# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"""Invariant represented by a non-relational expression.

Corresponds to non_relational_value_t in bCHLibTypes:

                                     tags[0]   tags    args
type non_relational_value_t =
| FSymbolicExpr of xpr_t              "sx"       1       1
| FIntervalValue of                   "iv"       1       2
    numerical_t option
    * numerical_t option
| FBaseOffsetValue of                 "bv"       1       4
    symbol_t
    * numerical_t option
    * numerical_t option
    * bool
"""

from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnInvDictionaryRecord, invregistry
from chb.invariants.XSymbol import XSymbol
from chb.invariants.XXpr import XXpr

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnInvDictionary import FnInvDictionary


class NonRelationalValue(FnInvDictionaryRecord):

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        FnInvDictionaryRecord.__init__(self, invd, ixval)

    @property
    def is_singleton(self) -> bool:
        return False

    @property
    def is_singleton_value(self) -> bool:
        return False

    @property
    def is_symbolic_expression(self) -> bool:
        return False

    @property
    def singleton_value(self) -> int:
        raise UF.CHBError("Non-relational-value is not a singleton")

    @property
    def expr(self) -> XXpr:
        raise UF.CHBError("Non-relational-value is not a symbolic expression")

    def to_json_result(self) -> JSONResult:
        return JSONResult(
            "nonrelationalvalue",
            {},
            "fail",
            "nonrelationalvalue: not yet implemented (" + self.tags[0] + ")")

    def __str__(self) -> str:
        return 'nrv:' + self.tags[0]


@invregistry.register_tag("sx", NonRelationalValue)
class NRVSymbolicExpr(NonRelationalValue):
    """Expression over symbolic constants.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        NonRelationalValue.__init__(self, invd, ixval)

    @property
    def is_symbolic_expression(self) -> bool:
        return True

    @property
    def expr(self) -> XXpr:
        return self.xd.xpr(self.args[0])

    def to_json_result(self) -> JSONResult:
        jxpr = self.expr.to_json_result()
        if jxpr.is_ok:
            content: Dict[str, Any] = {}
            content["kind"] = "sx"
            content["sym-expr"] = jxpr.content
            content["txtrep"] = str(self)
            return JSONResult("nonrelationalvalue", content, "ok")
        else:
            return JSONResult(
                "nonrelationalvalue",
                {},
                "fail",
                "nonrelationalvalue: " + str(jxpr.reason))

    def __str__(self) -> str:
        return str(self.expr)


@invregistry.register_tag("iv", NonRelationalValue)
class NRVIntervalValue(NonRelationalValue):
    """Ground interval value.

    args[0]: lowerbound; -1 if absent, otherwise index of numerical in xprdictionary
    args[1]: upperbound; -1 if absent, otherwise index of numerical in xprdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        NonRelationalValue.__init__(self, invd, ixval)

    @property
    def lowerbound(self) -> Optional[int]:
        if self.args[0] == -1:
            return None
        else:
            return self.xd.numerical(self.args[0]).value

    @property
    def upperbound(self) -> Optional[int]:
        if self.args[1] == -1:
            return None
        else:
            return self.xd.numerical(self.args[1]).value

    @property
    def is_bounded(self) -> bool:
        return self.lowerbound is not None and self.upperbound is not None

    @property
    def is_lower_bounded(self) -> bool:
        return self.lowerbound is not None

    @property
    def is_upper_bounded(self) -> bool:
        return self.upperbound is not None

    @property
    def is_singleton(self) -> bool:
        return self.is_bounded and self.lowerbound == self.upperbound

    @property
    def is_singleton_value(self) -> bool:
        return self.is_singleton

    @property
    def singleton_value(self) -> int:
        if self.is_singleton:
            lowerbound = self.lowerbound
            if lowerbound is not None:
                return lowerbound
            else:
                raise UF.CHBError("NRVIntervalValue: internal error")
        else:
            raise UF.CHBError("Non-relational-value is not a singleton")

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        if self.is_singleton_value:
            content["value"] = self.singleton_value
            content["kind"] = "civ"
        elif self.lowerbound is None:
            content["ub"] = self.upperbound
            content["kind"] = "ub-itv"
        elif self.upperbound is None:
            content["lb"] = self.lowerbound
            content["kind"] = "lb-itv"
        else:
            content["lb"] = self.lowerbound
            content["ub"] = self.upperbound
            content["kind"] = "itv"
        content["txtrep"] = str(self)
        return JSONResult("nonrelationalvalue", content, "ok")

    def __str__(self) -> str:
        if self.is_singleton:
            lb = cast(int, self.lowerbound)
            return hex(lb)
        elif self.is_bounded:
            lb = cast(int, self.lowerbound)
            ub = cast(int, self.upperbound)
            return "[" + hex(lb) + ";" + hex(ub) + "]"
        elif self.is_lower_bounded:
            return "[" + str(self.lowerbound) + "; ->"
        elif self.is_upper_bounded:
            return "<- ; " + str(self.upperbound) + "]"
        else:
            return "<- ; ->"


@invregistry.register_tag("bv", NonRelationalValue)
class NRVBaseOffsetValue(NonRelationalValue):
    """Fixed symbolic base with an offset expressed as a range.

    args[0]: index of base symbol in xprdictionary
    args[1]: lowerbound of offset
             -1 if absent, index of numerical in xprdictionary otherwise
    args[2]: upperbound of offset
             -1 if absent, index of numerical in xprdictionary otherwise
    args[4]: 1 if base can be NULL, 0 otherwise
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        NonRelationalValue.__init__(self, invd, ixval)

    @property
    def base(self) -> XSymbol:
        return self.xd.symbol(self.args[0])

    @property
    def lowerbound(self) -> Optional[int]:
        if self.args[1] == -1:
            return None
        else:
            return self.xd.numerical(self.args[1]).value

    @property
    def upperbound(self) -> Optional[int]:
        if self.args[2] == -1:
            return None
        else:
            return self.xd.numerical(self.args[2]).value

    @property
    def is_bounded(self) -> bool:
        return self.lowerbound is not None and self.upperbound is not None

    @property
    def is_lower_bounded(self) -> bool:
        return self.lowerbound is not None

    @property
    def is_upper_bounded(self) -> bool:
        return self.upperbound is not None

    @property
    def is_singleton(self) -> bool:
        return self.is_bounded and self.lowerbound == self.upperbound

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["base"] = str(self.base)
        if self.is_singleton:
            content["value"] = self.lowerbound
            content["kind"] = "b-civ"
        elif self.lowerbound is None and self.upperbound is None:
            content["kind"] = "b-unb"
        elif self.upperbound is None:
            content["lb"] = self.lowerbound
            content["kind"] = "b-lb-itv"
        elif self.lowerbound is None:
            content["ub"] = self.upperbound
            content["kind"] = "b-ub-itv"
        else:
            content["lb"] = self.lowerbound
            content["ub"] = self.upperbound
            content["kind"] = "b-itv"
        content["txtrep"] = str(self)
        return JSONResult("nonrelationalvalue", content, "ok")

    def __str__(self) -> str:
        if self.is_singleton and self.lowerbound == 0:
            return str(self.base.name)
        if self.is_singleton:
            return str(self.base) + " + " + str(self.lowerbound)
        elif self.is_bounded:
            return (str(self.base)
                    + "["
                    + str(self.lowerbound)
                    + ";"
                    + str(self.upperbound)
                    + "]")
        elif self.is_lower_bounded:
            return str(self.base) + "[" + str(self.lowerbound) + "; ->"
        elif self.is_upper_bounded:
            return str(self.base) + "<- ; " + str(self.upperbound) + "]"
        else:
            return str(self.base) + "<- ; ->"
