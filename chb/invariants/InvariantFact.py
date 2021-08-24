# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""Representation of single invariant at a particular location (address)

Corresponds to invariant_fact_t in bCHLibTypes:

                                                        tags[0]  tags   args
type invariant_fact_t =
  | Unreachable of string                                 "u"      2      0
      (* domain that signals unreachability *)
  | NonRelationalFact of                                  "n"      1      2
      variable_t
      * non_relational_value_t
  | RelationalFact of                                     "r"      1      1
      linear_equality_t
  | InitialVarEquality of                                 "ie"     1      2
      variable_t
      * variable_t (* variable, initial value *)
  | InitialVarDisEquality of                              "id"     1      2
      variable_t
      * variable_t (* variable, initial value *)
  | TestVarEquality of                                    "te"     3      2
      variable_t
      * variable_t
      * ctxt_iaddress_t
      * ctxt_iaddress_t   (* variable, test value *)

"""

from typing import List, Optional, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnInvDictionaryRecord, invregistry
from chb.invariants.LinearEquality import LinearEquality
from chb.invariants.NonRelationalValue import NonRelationalValue
from chb.invariants.XVariable import XVariable

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnInvDictionary import FnInvDictionary


class InvariantFact(FnInvDictionaryRecord):

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        FnInvDictionaryRecord.__init__(self, invd, ixval)

    def __str__(self) -> str:
        return "fact:" + self.tags[0]

    @property
    def is_unreachable(self) -> bool:
        return False

    @property
    def is_nonrelational(self) -> bool:
        return False

    @property
    def is_relational(self) -> bool:
        return False

    @property
    def is_initial_var_equality(self) -> bool:
        return False

    @property
    def is_initial_var_disequality(self) -> bool:
        return False

    @property
    def is_testvar_equality(self) -> bool:
        return False

    @property
    def variable(self) -> XVariable:
        raise UF.CHBError("variable not applicable to " + str(self))

    @property
    def value(self) -> NonRelationalValue:
        raise UF.CHBError("value not applicable to " + str(self))


@invregistry.register_tag("u", InvariantFact)
class UnreachableFact(InvariantFact):
    """Assertion that current location is not reachable.

    tags[1]: domain that signals unreachability
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        InvariantFact.__init__(self, invd, ixval)

    @property
    def is_unreachable(self) -> bool:
        return True

    @property
    def domain(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return "unreachable[" + self.domain + "]"


@invregistry.register_tag("n", InvariantFact)
class NRVFact(InvariantFact):
    """Assertion that a variable equals a symbolic expression.

    args[0]: index of variable in xprdictionary
    args[1]: index of non-relational-value in invdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        InvariantFact.__init__(self, invd, ixval)

    @property
    def is_nonrelational(self) -> bool:
        return True

    @property
    def variable(self) -> XVariable:
        return self.xd.variable(self.args[0])

    @property
    def value(self) -> NonRelationalValue:
        return self.invd.non_relational_value(self.args[1])

    def __str__(self) -> str:
        return str(self.variable) + ' == ' + str(self.value)


@invregistry.register_tag("ie", InvariantFact)
class InitialVarEqualityFact(InvariantFact):
    """Assertion that a variable still has its original value.

    args[0]: index of variable in xprdictionary
    args[1]: index of initial-value variable in xprdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        InvariantFact.__init__(self, invd, ixval)

    @property
    def is_initial_var_equality(self) -> bool:
        return True

    @property
    def variable(self) -> XVariable:
        return self.xd.variable(self.args[0])

    @property
    def initial_value(self) -> XVariable:
        return self.xd.variable(self.args[1])

    def __str__(self) -> str:
        return str(self.variable) + ' == ' + str(self.initial_value)


@invregistry.register_tag("id", InvariantFact)
class InitialVarDisEqualityFact(InvariantFact):
    """Assertion that a variable does not have its original value.

    args[0]: index of variable in xprdictionary
    args[1]: index of initial-value variable in xprdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        InvariantFact.__init__(self, invd, ixval)

    @property
    def is_initial_var_disequality(self) -> bool:
        return True

    @property
    def variable(self) -> XVariable:
        return self.xd.variable(self.args[0])

    @property
    def initial_value(self) -> XVariable:
        return self.xd.variable(self.args[1])

    def __str__(self) -> str:
        return str(self.variable) + ' != ' + str(self.initial_value)


@invregistry.register_tag("te", InvariantFact)
class TestVarEqualityFact(InvariantFact):
    """Assertion that a variable did not change from test location to jump location.

    tags[1]: address of test location
    tags[2]: address of conditional jump location
    args[0]: index of test variable in xprdictionary
    args[1]: index of test-value variable in xprdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        InvariantFact.__init__(self, invd, ixval)

    @property
    def is_testvar_equality(self) -> bool:
        return True

    @property
    def testvariable(self) -> XVariable:
        return self.xd.variable(self.args[0])

    @property
    def testvalue(self) -> XVariable:
        return self.xd.variable(self.args[1])

    @property
    def testaddr(self) -> str:
        return self.tags[1]

    @property
    def jumpaddr(self) -> str:
        return self.tags[2]

    def __str__(self) -> str:
        return (str(self.testvariable)
                + "@"
                + self.testaddr
                + " = "
                + str(self.testvalue)
                + "@"
                + self.jumpaddr)


@invregistry.register_tag("r", InvariantFact)
class RelationalFact(InvariantFact):

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        InvariantFact.__init__(self, invd, ixval)

    @property
    def is_relational(self) -> bool:
        return True

    @property
    def equality(self) -> LinearEquality:
        return self.invd.linear_equality(self.args[0])

    def __str__(self) -> str:
        return str(self.equality)
