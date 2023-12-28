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
"""Parameter location

Based on parameter_location_t in bchlib/bCHLibTypes:
                                                    tags[0]   tags   args
type parameter_location_t
  StackParameter of int                              "s"        1      1
  RegisterParameter of register_t                    "r"        1      1
  GlobalParameter of doubleword_int                  "g"        1      1
  UnknownParameterLocation                           "u"        1      0
"""

from typing import List, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import (
    InterfaceDictionaryRecord, apiregistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.BDictionary import AsmAddress
    from chb.app.Register import Register


class FtsParameterLocation(InterfaceDictionaryRecord):
    """Location of parameter in function type signature.

    These are generic locations, and not necessarily the real locations where
    arguments are located. For example, for mips, the four argument registers
    a0, .. a3, are represented as stack locations 1..4.
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def is_stack_parameter(self) -> bool:
        return False

    @property
    def is_register_parameter(self) -> bool:
        return False

    @property
    def is_global_parameter(self) -> bool:
        return False

    @property
    def is_unknown_location(self) -> bool:
        return False

    def is_register_parameter_location_of(self, r: "Register") -> bool:
        return False


@apiregistry.register_tag("s", FtsParameterLocation)
class FtsStackParameter(FtsParameterLocation):
    """stack parameter (real or canonical)

    args[0]: index of stack parameter (starting at 1)
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FtsParameterLocation.__init__(self, ixd, ixval)

    @property
    def is_stack_parameter(self) -> bool:
        return True

    @property
    def index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return "stack-parameter " + str(self.index)


@apiregistry.register_tag("r", FtsParameterLocation)
class FtsRegisterParameter(FtsParameterLocation):
    """register parameter (used only for fastcall).

    args[0]: index of register in bdictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FtsParameterLocation.__init__(self, ixd, ixval)

    @property
    def is_register_parameter(self) -> bool:
        return True

    @property
    def register(self) -> "Register":
        return self.bd.register(self.args[0])

    def is_register_parameter_location_of(self, r: "Register") -> bool:
        return str(self.register) == str(r)

    def __str__(self) -> str:
        return "register-parameter " + str(self.register)


@apiregistry.register_tag("g", FtsParameterLocation)
class FtsGlobalParameter(FtsParameterLocation):
    """global parameter (not a real parameter, only used to indicate dependency).

    args[0]: index of global variable address in bdictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FtsParameterLocation.__init__(self, ixd, ixval)

    @property
    def is_global_parameter(self) -> bool:
        return True

    @property
    def address(self) -> "AsmAddress":
        return self.bd.address(self.args[0])

    def __str__(self) -> str:
        return "global-parameter " + str(self.address)


@apiregistry.register_tag("u", FtsParameterLocation)
class FtsUnknownLocation(FtsParameterLocation):
    """location that is unknown."""

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FtsParameterLocation.__init__(self, ixd, ixval)

    @property
    def is_unknown_location(self) -> bool:
        return True
        
