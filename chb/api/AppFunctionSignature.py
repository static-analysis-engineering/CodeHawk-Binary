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
    from chb.api.FtsParameter import FtsParameter
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.Register import Register
    from chb.bctypes.BCTyp import BCTyp


class AppFunctionSignature(InterfaceDictionaryRecord):
    """Function type signature.

    tags[0]: calling convention
    args[0]: index of parameter list in interfacedictionary
    args[1]: 1 if varargs, 0 otherwise
    args[2]: va-list or -1
    args[3]: index of returntype in bcdictionary
    args[4]: index of parameter roles in interfacedictionary
    args[5]: stack adjustment or -1
    args[6..]: indices of registers preserved (not normally preserved)
    """

    def __init__(self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def calling_convention(self) -> str:
        return self.tags[0]

    @property
    def parameter_list(self) -> List["FtsParameter"]:
        return self.id.fts_parameter_list(self.args[0])

    @property
    def returntype(self) -> "BCTyp":
        return self.bcd.typ(self.args[3])

    def index_of_register_parameter_location(self, r: "Register") -> Optional[int]:
        for p in self.parameter_list:
            if p.is_register_parameter_location(r):
                return p.argindex
        return None

    def __str__(self) -> str:
        return (
            str(self.returntype)
            + " ("
            + ", ".join(str(p) for p in self.parameter_list)
            + ")")
        
