# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
"""Term used in external interface descriptions (function api's).

Note: The file chb/models/BTerm describes the same data type as the BTerm in
this file. The difference between the two files is the manner in which the
bterms are saved. The models file contains the bterms as encountered in the
legacy function summaries (explicit xml), whereas the bterms found in this
file represent indexed terms obtained from the interface dictionary.

Based on bterm_t in bchlib/bCHLibTypes:
                                                    tags[0]   tags   args
type bterm_t =
  | ArgValue of fts_parameter_t                       "a"       1      1
  | RunTimeValue                                     "rt"       1      0
  | ReturnValue                                       "r"       1      0
  | NamedConstant of string                           "n"       1      1
  | ArgNullTerminatorPos of bterm_t                  "nt"       1      1
  | NumConstant of numerical_t                        "c"       2      0
  | ArgBufferSize of bterm_t                          "s"       1      1
  | IndexSize of bterm_t                              "i"       1      1
  | ByteSize of bterm_t                               "b"       1      1
  | ArgAddressedValue of bterm_t * bterm_t           "aa"       1      2
  | ArgSizeOf of btype                               "as"       1      1
  | ArithmeticExpr of ...
"""

from typing import List, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import (
    InterfaceDictionaryRecord, apiregistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import FtsParameter
    from chb.api.InterfaceDictionary import InterfaceDictionary


class BTerm(InterfaceDictionaryRecord):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def is_argvalue(self) -> bool:
        return False


@apiregistry.register_tag("a", BTerm)
class BTermArgValue(BTerm):
    """Reference to an argument value.

    args[0]: index of fts parameter in interface dictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        BTerm.__init__(self, ixd, ixval)

    @property
    def parameter(self) -> "FtsParameter":
        return self.id.fts_parameter(self.args[0])

    @property
    def is_argvalue(self) -> bool:
        return True

    def __str__(self) -> str:
        return "arg-value(" + str(self.parameter) + ")"


@apiregistry.register_tag("rt", BTerm)
class BTermRunTimeValue(BTerm):
    """Unknown value determined at runtime."""

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        BTerm.__init__(self, ixd, ixval)

    def __str__(self) -> str:
        return "runtime-value"


@apiregistry.register_tag("nt", BTerm)
class BTermArgNullTerminatorPos(BTerm):
    """Size determined by the position of the null-terminator byte.

    args[0]: index of bterm in interface dictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        BTerm.__init__(self, ixd, ixval)

    @property
    def bterm(self) -> BTerm:
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "null-terminator-pos(" + str(self.bterm) + ")"


@apiregistry.register_tag("i", BTerm)
class BTermIndexSize(BTerm):
    """Size expressed in units of underlying data type size.

    args[0]: index of bterm in interface dictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        BTerm.__init__(self, ixd, ixval)

    @property
    def bterm(self) -> BTerm:
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "index-size(" + str(self.bterm) + ")"


@apiregistry.register_tag("c", BTerm)
class BTermNumConstant(BTerm):
    """Constant numerical term.

    tags[1]: numerical value represented as a string
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        BTerm.__init__(self, ixd, ixval)

    @property
    def constant(self) -> int:
        return int(self.tags[1])

    def __str__(self) -> str:
        return str(self.constant)
