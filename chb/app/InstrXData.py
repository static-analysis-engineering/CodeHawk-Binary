# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
"""Abstract superclass of instruction invariants.

Subclasses:
 - MIPSInstrXData
 - ARMInstrXData
"""


from typing import List, Tuple, TYPE_CHECKING

import chb.app.BDictionary as B
import chb.app.DictionaryRecord as D
import chb.invariants.BXpr as X
import chb.util.fileutil as UF


if TYPE_CHECKING:
    import chb.app.BDictionary
    import chb.app.Function
    import chb.app.FunctionDictionary
    import chb.invariants.FnVarDictionary
    import chb.invariants.FnXprDictionary


class InstrXData(D.DictionaryRecord):

    def __init__(
            self,
            d: "chb.app.FunctionDictionary.FunctionDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.DictionaryRecord.__init__(self, index, tags, args)
        self._d = d
        self._vd = self._d.function.vardictionary
        self._xd = self._d.function.xprdictionary

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self.function.app

    @property
    def function(self) -> "chb.app.Function.Function":
        return self._d.function

    @property
    def vardictionary(self) -> "chb.invariants.FnVarDictionary.FnVarDictionary":
        return self._vd

    @property
    def xprdictionary(self) -> "chb.invariants.FnXprDictionary.FnXprDictionary":
        return self._xd

    @property
    def bdictionary(self) -> "chb.app.BDictionary.BDictionary":
        return self.app.bdictionary

    @property
    def xprdata(self) -> Tuple[List[str], List[int], List[X.BXXprBase]]:
        if len(self.tags) == 0:
            return ([], self.args, [])
        key = self.tags[0]
        if key.startswith("a:"):
            xprs = []
            keyletters = key[2:]
            for (i, c) in enumerate(keyletters):
                arg = self.args[i]
                xd = self.xprdictionary
                bd = self.bdictionary
                if c == "v":
                    xprs.append(xd.get_variable(arg))
                elif c == "x":
                    xprs.append(xd.get_xpr(arg))
                elif c == "a":
                    xprs.append(xd.get_xpr(arg))
                elif c == "s":
                    xprs.append(bd.get_string(arg))
                elif c == "i":
                    xprs.append(xd.get_interval(arg))
                elif c == "l":
                    xprs.append(arg)
                else:
                    raise UF.CHBError("Key letter not recognized: " + c)
            return (self.tags[1:], self.args, xprs)
        return (self.tags, self.args, [])

    @property
    def is_function_argument(self) -> bool:
        return len(self.tags) > 1 and self.tags[1] == "arg"

    @property
    def function_argument_callsite(self) -> B.AsmAddress:
        if self.is_function_argument:
            return self.bdictionary.get_address(self.args[2])
        raise UF.CHBError("Operand is not a functon argument")

    def get_xprdata(self): return self.xprdata
