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

from typing import Optional, TYPE_CHECKING

import chb.invariants.InputConstraintValue as ICV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.invariants.XXpr


class InputConstraint:

    def __init__(self) -> None:
        pass

    def is_env_test(self) -> bool:
        return False

    def is_env_absent(self) -> bool:
        return False

    def is_string_starts_with(self) -> bool:
        return False

    def is_string_not_starts_with(self) -> bool:
        return False

    def is_string_equals(self) -> bool:
        return False

    def is_string_not_equals(self) -> bool:
        return False

    def is_string_contains(self) -> bool:
        return False

    def is_string_not_contains(self) -> bool:
        return False


class EnvironmentTestConstraint(InputConstraint):

    def __init__(self, name: str):
        InputConstraint.__init__(self)
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def is_env_test(self) -> bool:
        return True

    def __str__(self) -> str:
        return "env(" + self.name + ")"


class EnvironmentAbsentConstraint(InputConstraint):

    def __init__(self, name: str):
        InputConstraint.__init__(self)
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def is_env_absent(self) -> bool:
        return True

    def __str__(self) -> str:
        return "!env(" + self.name + ")"


class StringEqualsConstraint(InputConstraint):

    def __init__(
            self,
            stringexpr: ICV.InputConstraintValue,
            stringconst: "chb.invariants.XXpr.XXpr",
            case_insensitive: bool = False) -> None:
        InputConstraint.__init__(self)
        self._stringexpr = stringexpr
        self._stringconst = stringconst
        self.case_insensitive = case_insensitive

    @property
    def stringexpr(self) -> ICV.InputConstraintValue:
        return self._stringexpr

    @property
    def stringconst(self) -> "chb.invariants.XXpr.XXpr":
        return self._stringconst

    def is_string_equals(self) -> bool:
        return True

    def __str__(self) -> str:
        predicate = "equalsIgnoreCase" if self.case_insensitive else "equals"
        return (predicate
                + "("
                + str(self.stringexpr)
                + ","
                + str(self.stringconst)
                + ")")


class StringNotEqualsConstraint(InputConstraint):

    def __init__(
            self,
            stringexpr: ICV.InputConstraintValue,
            stringconst: "chb.invariants.XXpr.XXpr",
            case_insensitive: bool = False) -> None:
        InputConstraint.__init__(self)
        self._stringexpr = stringexpr
        self._stringconst = stringconst
        self.case_insensitive = case_insensitive

    @property
    def stringexpr(self) -> ICV.InputConstraintValue:
        return self._stringexpr

    @property
    def stringconst(self) -> "chb.invariants.XXpr.XXpr":
        return self._stringconst

    def is_string_not_equals(self) -> bool:
        return True

    def __str__(self) -> str:
        predicate = "equalsIgnoreCase" if self.case_insensitive else "equals"
        return ("!"
                + predicate
                + "("
                + str(self.stringexpr)
                + ","
                + str(self.stringconst)
                + ")")


class StringStartsWithConstraint(InputConstraint):

    def __init__(
            self,
            stringexpr: ICV.InputConstraintValue,
            stringconst: "chb.invariants.XXpr.XXpr",
            length: Optional[int] = None,
            case_insensitive: bool = False) -> None:
        InputConstraint.__init__(self)
        self._stringexpr = stringexpr
        self._stringconst = stringconst
        self._length = length
        self.case_insensitive = case_insensitive

    @property
    def stringexpr(self) -> ICV.InputConstraintValue:
        return self._stringexpr

    @property
    def stringconst(self) -> "chb.invariants.XXpr.XXpr":
        return self._stringconst

    @property
    def length(self) -> int:
        if self._length is not None:
            return self._length
        else:
            raise UF.CHBError("String constraint has no length: "
                              + str(self))

    def has_length(self) -> bool:
        return self._length is not None

    def is_string_starts_with(self) -> bool:
        return True

    def __str__(self) -> str:
        predicate = "startswithIgnoreCase" if self.case_insensitive else "startswith"
        return (predicate
                + '(' +
                str(self.stringexpr)
                + ','
                + str(self.stringconst)
                + ')')


class StringNotStartsWithConstraint(InputConstraint):

    def __init__(
            self,
            stringexpr: ICV.InputConstraintValue,
            stringconst: "chb.invariants.XXpr.XXpr",
            length: Optional[int] = None,
            case_insensitive: bool = False) -> None:
        InputConstraint.__init__(self)
        self._stringexpr = stringexpr
        self._stringconst = stringconst
        self._length = length
        self.case_insensitive = case_insensitive

    @property
    def stringexpr(self) -> ICV.InputConstraintValue:
        return self._stringexpr

    @property
    def stringconst(self) -> "chb.invariants.XXpr.XXpr":
        return self._stringconst

    @property
    def length(self) -> int:
        if self._length is not None:
            return self._length
        else:
            raise UF.CHBError("String constraint has no length: "
                              + str(self))

    def has_length(self) -> bool:
        return self._length is not None

    def is_string_not_starts_with(self) -> bool:
        return True

    def __str__(self) -> str:
        predicate = "startswithIgnoreCase" if self.case_insensitive else "startswith"
        return ("!"
                + predicate
                + "(" +
                str(self.stringexpr)
                + ","
                + str(self.stringconst)
                + ")")


class StringContainsConstraint(InputConstraint):

    def __init__(
            self,
            stringexpr: ICV.InputConstraintValue,
            stringconst: str) -> None:
        InputConstraint.__init__(self)
        self._stringexpr = stringexpr
        self._stringconst = stringconst

    @property
    def stringexpr(self) -> ICV.InputConstraintValue:
        return self._stringexpr

    @property
    def stringconst(self) -> str:
        return self._stringconst

    def is_string_contains(self) -> bool:
        return True

    def __str__(self) -> str:
        return ("contains("
                + str(self.stringexpr)
                + ','
                + self.stringconst
                + ')')


class StringNotContainsConstraint(InputConstraint):

    def __init__(
            self,
            stringexpr: ICV.InputConstraintValue,
            stringconst: str) -> None:
        InputConstraint.__init__(self)
        self._stringexpr = stringexpr
        self._stringconst = stringconst

    @property
    def stringexpr(self) -> ICV.InputConstraintValue:
        return self._stringexpr

    @property
    def stringconst(self) -> str:
        return self._stringconst

    def is_string_not_contains(self) -> bool:
        return True

    def __str__(self) -> str:
        return ("!contains("
                + str(self.stringexpr)
                + ","
                + str(self.stringconst)
                + ")")
