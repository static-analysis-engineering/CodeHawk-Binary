# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023 Aarno Labs LLC
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
"""Representation of single variable invariant at a particular location (address)

"""


from typing import List, Optional, Sequence, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import (
    FnVarInvDictionaryRecord, varinvregistry)
from chb.invariants.VarDefUse import VarDefUse
from chb.invariants.XSymbol import XSymbol
from chb.invariants.XVariable import XVariable

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnVarInvDictionary import FnVarInvDictionary


class VarInvariantFact(FnVarInvDictionaryRecord):

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarInvDictionaryRecord.__init__(self, varinvd, ixval)

    def __str__(self) -> str:
        return "varfact:" + self.tags[0]

    @property
    def vardefuse(self) -> VarDefUse:
        return self.varinvd.vardefuse(self.args[0])

    @property
    def variable(self) -> XVariable:
        return self.vardefuse.variable

    @property
    def is_reaching_def(self) -> bool:
        return False

    @property
    def is_flag_reaching_def(self) -> bool:
        return False


@varinvregistry.register_tag("r", VarInvariantFact)
class ReachingDefFact(VarInvariantFact):
    """Assertion that the definitions made at these locations may reach here.

    args[0]: index of vardef use in varinvdictionary
    """

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        VarInvariantFact.__init__(self, varinvd, ixval)

    @property
    def is_reaching_def(self) -> bool:
        return True

    @property
    def deflocations(self) -> Sequence[XSymbol]:
        return self.vardefuse.symbols

    def __str__(self) -> str:
        return "RD: " + str(self.vardefuse)


@varinvregistry.register_tag("f", VarInvariantFact)
class FlagReachingDefFact(VarInvariantFact):
    """Assertion that the flag definitions made at these locations may reach here.

    args[0]: index of vardef use in varinvdictionary
    """

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        VarInvariantFact.__init__(self, varinvd, ixval)

    @property
    def is_flag_reaching_def(self) -> bool:
        return True

    @property
    def deflocations(self) -> Sequence[XSymbol]:
        return self.vardefuse.symbols

    def __str__(self) -> str:
        return "FRD: " + str(self.vardefuse)


@varinvregistry.register_tag("d", VarInvariantFact)
class DefUse(VarInvariantFact):
    """Assertion that the definition is used at this location.

    args[0]: index of vardef use in varinvdictionary
    """

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        VarInvariantFact.__init__(self, varinvd, ixval)

    @property
    def is_def_use(self) -> bool:
        return True

    @property
    def uselocations(self) -> Sequence[XSymbol]:
        return self.vardefuse.symbols

    def __str__(self) -> str:
        return "DU: " + str(self.vardefuse)


@varinvregistry.register_tag("h", VarInvariantFact)
class DefUseHigh(VarInvariantFact):
    """Assertion that the definition is used at this location.

    args[0]: index of vardef use in varinvdictionary
    """

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        VarInvariantFact.__init__(self, varinvd, ixval)

    @property
    def is_def_use_high(self) -> bool:
        return True

    @property
    def uselocations(self) -> Sequence[XSymbol]:
        return self.vardefuse.symbols

    def __str__(self) -> str:
        return "DU-H: " + str(self.vardefuse)
