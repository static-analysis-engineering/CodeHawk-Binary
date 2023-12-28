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


from typing import List, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import InterfaceDictionaryRecord

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.FtsParameterLocation import FtsParameterLocation
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.Register import Register
    from chb.bctypes.BCTyp import BCTyp


class FtsParameter(InterfaceDictionaryRecord):
    """Function type signature parameter.

    tags[0]: arg_io_mfts
    tags[1]: formatstring type
    args[0]: parameter index
    args[1]: index of parameter name in bdictionary
    args[2]: index of parameter type in bcdictionary
    args[3]: index of description of bdictionary
    args[4]: index of parameter roles in interfacedictionary
    args[5]: size in bytes
    args[6]: index of parameter location list in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def name(self) -> str:
        return self.bd.string(self.args[1])

    @property
    def argindex(self) -> int:
        return self.args[0]

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[2])

    @property
    def parameter_location_list(self) -> List["FtsParameterLocation"]:
        return self.id.parameter_location_list(self.args[6])

    def is_register_parameter_location(self, r: "Register") -> bool:
        if len(self.parameter_location_list) == 1:
            return self.parameter_location_list[0].is_register_parameter_location_of(r)
        return False

    def __str__(self) -> str:
        return str(self.typ) + " " + str(self.name)
