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

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.invariants.XXpr


class InputConstraintValue:

    def __init__(self) -> None:
        pass

    @property
    def is_env_value(self) -> bool:
        return False

    @property
    def is_string_suffix_value(self) -> bool:
        return False

    @property
    def is_command_line_argument(self) -> bool:
        return False

    @property
    def is_constraint_value_expr(self) -> bool:
        return False

    @property
    def is_function_argument_value(self) -> bool:
        return False


class EnvironmentInputValue(InputConstraintValue):

    def __init__(self, name: str) -> None:
        InputConstraintValue.__init__(self)
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_env_value(self) -> bool:
        return True

    def __str__(self) -> str:
        return "env(" + self.name + ")"


class StringSuffixValue(InputConstraintValue):

    def __init__(
            self,
            stringexpr: InputConstraintValue,
            charcode: str,
            lastpos: bool = False):
        InputConstraintValue.__init__(self)
        self._stringexpr = stringexpr
        self._charcode = charcode
        self._lastpos = lastpos

    @property
    def stringexpr(self) -> InputConstraintValue:
        return self._stringexpr

    @property
    def charcode(self) -> str:
        return self._charcode

    @property
    def is_last_position(self) -> bool:
        return self._lastpos

    @property
    def is_string_suffix_value(self) -> bool:
        return True

    def __str__(self) -> str:
        pos = 'lastpos' if self.is_last_position else 'pos'
        return ("suffix("
                + str(self.stringexpr)
                + ','
                + pos
                + '('
                + self.charcode
                + '))')


class FunctionArgumentValue(InputConstraintValue):

    def __init__(self, argindex: int) -> None:
        InputConstraintValue.__init__(self)
        self._argindex = argindex

    @property
    def argindex(self) -> int:
        return self._argindex

    @property
    def is_function_argument_value(self) -> bool:
        return True

    def __str__(self) -> str:
        return "function-arg(" + str(self.argindex) + ")"


class CommandLineArgument(InputConstraintValue):

    def __init__(self, argindex: int) -> None:
        InputConstraintValue.__init__(self)
        self._argindex = argindex

    @property
    def argindex(self) -> int:
        return self._argindex

    @property
    def is_command_line_argument(self) -> bool:
        return True

    def __str__(self) -> str:
        return 'cmdline-arg(' + str(self.argindex) + ')'


class InputConstraintValueExpr(InputConstraintValue):

    def __init__(self,
                 op: str,
                 x: InputConstraintValue,
                 y: str):
        InputConstraintValue.__init__(self)
        self._op = op
        self._x = x
        self._y = y

    @property
    def operator(self) -> str:
        return self._op

    @property
    def arg1(self) -> InputConstraintValue:
        return self._x

    @property
    def arg2(self) -> str:
        return self._y

    @property
    def is_constraint_value_expr(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.arg1) + self.operator + str(self.arg2)
