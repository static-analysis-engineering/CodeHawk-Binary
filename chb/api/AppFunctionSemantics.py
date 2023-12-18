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
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.api.XXPredicate import XXPredicate


class AppFunctionSemantics(InterfaceDictionaryRecord):
    """Function semantics (preconditions, postconditions, side effects).

    args[0]: index of precondition list in interfacedictionary
    args[1]: index of postcondition list in interfacedictionary
    args[2]: index of error-postcondition list in interfacedictionary
    args[3]: index of side-effect list in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def precondition_list(self) -> List["XXPredicate"]:
        return self.id.xpredicate_list(self.args[0])

    @property
    def postcondition_list(self) -> List["XXPredicate"]:
        return self.id.xpredicate_list(self.args[1])

    @property
    def errorpostcondition_list(self) -> List["XXPredicate"]:
        return self.id.xpredicate_list(self.args[2])

    @property
    def sideeffect_list(self) -> List["XXPredicate"]:
        return self.id.xpredicate_list(self.args[3])

    def __str__(self) -> str:
        lines: List[str] = []
        if len(self.precondition_list) > 0:
            lines.append("Preconditions")
            for p in self.precondition_list:
                lines.append("  " + str(p))
        if len(self.postcondition_list) > 0:
            lines.append("Postconditions")
            for p in self.postcondition_list:
                lines.append("  " + str(p))
        if len(self.errorpostcondition_list) > 0:
            for p in self.errorpostcondition_list:
                lines.append("Error postconditions")
                lines.append("  " + str(p))
        if len(self.sideeffect_list) > 0:
            lines.append("Side-effects")
            for p in self.sideeffect_list:
                lines.append("  " + str(p))
        return "\n".join(lines)
