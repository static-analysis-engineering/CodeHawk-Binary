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


from typing import List, Optional, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import InterfaceDictionaryRecord

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.AppFunctionSignature import AppFunctionSignature
    from chb.api.FtsParameterLocation import FtsParameterLocation
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.bctypes.BCTyp import BCTyp


class AppFunctionInterface(InterfaceDictionaryRecord):
    """Function signature and parameter roles.

    args[0]: index of function interface name
    args[1]: jni index or -1
    args[2]: syscall index of -1
    args[3]: index of function signature in interfacedictionary
    args[4]: index of parameter locations list in interfacedictionary
    args[5]: index of inferred return type or -1 if not inferred
    args[6]: index of externally provided type or -1 if not available
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def name(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def signature(self) -> "AppFunctionSignature":
        return self.id.function_signature(self.args[3])

    @property
    def parameter_locations(self) -> List["FtsParameterLocation"]:
        return self.id.parameter_location_list(self.args[4])

    @property
    def bctype(self) -> Optional["BCTyp"]:
        if self.args[6] > 0:
            return self.bcd.typ(self.args[6])
        else:
            return None

    def __str__(self) -> str:
        return (
            self.name + " "
            + str(self.signature)
            + "\nparameters: ("
            + ", ".join(str(loc) for loc in self.parameter_locations)
            + ")")
        
