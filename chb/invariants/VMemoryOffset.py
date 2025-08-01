# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2025 Aarno Labs LLC
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
"""Memory offset representation.

Represents memory_offset_t in bchlib/bCHLibTypes:
                                                       tags[0]  tags   args
type memory_offset_t =
  | NoOffset                                             "n"      1      0
  | ConstantOffset of numerical_t * memory_offset_t      "c"      2      1
  | FieldOffset of string * int * memory_offset_t        "f"      2      2
  | IndexOffset of variable_t * int * memory_offset_t    "i"      1      3
  | ArrayIndexOffset of xpr_t * memory_offset_t          "a"      1      2
  | BasePtrArrayIndexOffset of xpr_t * memory_offset_t   "p"      1      2
  | UnknownOffset                                        "u"      1      0

"""

from typing import Any, Dict, List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class VMemoryOffset(FnVarDictionaryRecord):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def is_constant_offset(self) -> bool:
        return False

    @property
    def is_constant_value_offset(self) -> bool:
        return False

    @property
    def is_field_offset(self) -> bool:
        return False

    @property
    def is_index_offset(self) -> bool:
        return False

    @property
    def is_array_index_offset(self) -> bool:
        return False

    @property
    def is_baseptr_array_index_offset(self) -> bool:
        return False

    @property
    def is_no_offset(self) -> bool:
        return False

    @property
    def is_unknown_offset(self) -> bool:
        return False

    @property
    def offset(self) -> "VMemoryOffset":
        raise UF.CHBError(
            "offset is not supported for "
            + str(self)
            + " ("
            + self.tags[0]
            + ")")

    @property
    def offsetconstant(self) -> int:
        raise UF.CHBError(
            "Offsetconstant is not supported for "
            + str(self)
            + " ("
            + self.tags[0]
            + ")")

    def has_no_offset(self) -> bool:
        return False

    def offsetvalue(self) -> int:
        raise UF.CHBError(
            "Offsetvalue is not supported for "
            + str(self)
            + " ("
            + self.tags[0]
            + ")")

    def to_json_result(self) -> JSONResult:
        return JSONResult(
            "memoryoffset",
            {},
            "fail",
            "memoryoffset: not yet implemented (" + self.tags[0] + ")")

    def __str__(self) -> str:
        return "memory-offset:" + self.tags[0]


@varregistry.register_tag("n", VMemoryOffset)
class VMemoryOffsetNoOffset(VMemoryOffset):
    """No offset. """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def is_no_offset(self) -> bool:
        return True

    @property
    def is_constant_value_offset(self) -> bool:
        return True

    def offsetvalue(self) -> int:
        return 0

    def to_json_result(self) -> JSONResult:
        return JSONResult("memoryoffset", {"kind": "none"}, "ok")

    def __str__(self) -> str:
        return ""


@varregistry.register_tag("c", VMemoryOffset)
class VMemoryOffsetConstantOffset(VMemoryOffset):
    """Constant offset.

    tags[1]: constant offset (string)
    args[0]: index of next-level offset in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[0])

    @property
    def is_constant_offset(self) -> bool:
        return True

    @property
    def is_constant_value_offset(self) -> bool:
        return self.has_no_offset()

    @property
    def offsetconstant(self) -> int:
        return int(self.tags[1])

    def offsetvalue(self) -> int:
        if self.is_constant_value_offset:
            return int(self.tags[1]) + self.offset.offsetvalue()
        else:
            raise UF.CHBError("Has additional offset: " + str(self.offset))

    def has_no_offset(self) -> bool:
        return self.offset.is_no_offset

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        if self.is_constant_value_offset:
            content["value"] = self.offsetvalue()
            content["kind"] = "cv"
        else:
            content["value"] = self.offsetconstant
            content["kind"] = "cvo"
            content["suboffset"] = self.offset.to_json_result()
        content["txtrep"] = str(self)
        return JSONResult("memoryoffset", content, "ok")

    def __str__(self) -> str:
        if self.has_no_offset():
            return str(self.offsetvalue())
        elif self.offset.is_constant_offset:
            return str(self.offsetconstant) + "[" + str(self.offset.offsetvalue()) + "]"
        else:
            return str(self.offsetconstant) + "." + str(self.offset)


@varregistry.register_tag("f", VMemoryOffset)
class VMemoryOffsetFieldOffset(VMemoryOffset):
    """Field offset

    tags[1]: fieldname
    args[0]: compinfo key
    args[1]: index of next-level offset in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def fieldname(self) -> str:
        return self.tags[1]

    @property
    def ckey(self) -> int:
        return self.args[0]

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[1])

    @property
    def is_field_offset(self) -> bool:
        return True

    def has_no_offset(self) -> bool:
        return self.offset.is_no_offset

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        if self.has_no_offset():
            content["kind"] = "fv"
            content["fieldname"] = self.fieldname
            content["ckey"] = self.ckey
        else:
            fmem = self.offset.to_json_result()
            if not fmem.is_ok:
                return JSONResult("memoryoffset", {}, "fail", fmem.reason)
            content["kind"] = "fvo"
            content["fieldname"] = self.fieldname
            content["ckey"] = self.ckey
            content["suboffset"] = fmem.content
        content["txtrep"] = str(self)
        return JSONResult("memoryoffset", content, "ok")

    def __str__(self) -> str:
        return "." + self.fieldname + str(self.offset)


@varregistry.register_tag("i", VMemoryOffset)
class VMemoryOffsetIndexOffset(VMemoryOffset):
    """Index offset.

    args[0]: index of indexvariable in xprdictionary
    args[1]: size of element
    args[2]: index of next-level offset in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def indexvariable(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    @property
    def elementsize(self) -> int:
        return self.args[1]

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[2])

    @property
    def is_index_offset(self) -> bool:
        return True

    def has_no_offset(self) -> bool:
        return self.offset.is_no_offset

    def to_json_result(self) -> JSONResult:
        jvar = self.indexvariable.to_json_result()
        if not jvar.is_ok:
            return JSONResult("memoryoffset", {}, "fail", jvar.reason)
        content: Dict[str, Any] = {}
        if self.has_no_offset():
            content["kind"] = "iv"
            content["ixvar"] = jvar.content
            content["elsize"] = self.elementsize
        else:
            jmem = self.offset.to_json_result()
            if not jmem.is_ok:
                return JSONResult("memoryoffset", {}, "fail", jmem.reason)
            content["kind"] = "ivo"
            content["ixvar"] = jvar.content
            content["elsize"] = self.elementsize
            content["suboffset"] = jmem.content
        content["txtrep"] = str(self)
        return JSONResult("memoryoffset", content, "ok")

    def __str__(self) -> str:
        return "[" + str(self.indexvariable) + "]" + str(self.offset)


@varregistry.register_tag("a", VMemoryOffset)
class VMemoryOffsetArrayIndexOffset(VMemoryOffset):
    """Array index offset

    args[0]: index of index expression in xprdictionary
    args[1]: index of next-level offset in vardictionary

    Note: the difference with IndexOffset is that the index expression is
    already scaled for the size of the array element (that is, it is similar
    to a C index expression).
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def index_expression(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[1])

    @property
    def is_array_index_offset(self) -> bool:
        return True

    def has_no_offset(self) -> bool:
        return self.offset.is_no_offset

    def to_json_result(self) -> JSONResult:
        jxpr = self.index_expression.to_json_result()
        if not jxpr.is_ok:
            return JSONResult("memoryoffset", {}, "fail", jxpr.reason)
        content: Dict[str, Any] = {}
        if self.has_no_offset():
            content["kind"] = "aiv"
            content["aixpr"] = jxpr.content
        else:
            jmem = self.offset.to_json_result()
            if not jmem.is_ok:
                return JSONResult("memoryoffset", {}, "fail", jmem.reason)
            content["kind"] = "aivo"
            content["aixpr"] = jxpr.content
            content["suboffset"] = jmem.content
        content["txtrep"] = str(self)
        return JSONResult("memoryoffset", content, "ok")

    def __str__(self) -> str:
        return "[" + str(self.index_expression) + "]" + str(self.offset)


@varregistry.register_tag("p", VMemoryOffset)
class VMemoryOffsetBasePtrArrayIndexOffset(VMemoryOffset):
    """Array index offset

    args[0]: index of index expression in xprdictionary
    args[1]: index of next-level offset in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def index_expression(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[1])

    @property
    def is_baseptr_array_index_offset(self) -> bool:
        return True

    def has_no_offset(self) -> bool:
        return self.offset.is_no_offset

    def __str__(self) -> str:
        return "[" + str(self.index_expression) + "]" + str(self.offset)


@varregistry.register_tag("u", VMemoryOffset)
class VMemoryOffsetUnknown(VMemoryOffset):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def is_unknown_offset(self) -> bool:
        return True

    def __str__(self) -> str:
        return "?"
