# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
"""Symbolic value, identified by name and sequence number"""

from typing import Any, Dict, List, Tuple, TYPE_CHECKING

from chb.app.Register import Register

from chb.invariants.FnDictionaryRecord import FnXprDictionaryRecord
from chb.invariants.VAssemblyVariable import VAssemblyVariable
from chb.invariants.XSymbol import XSymbol

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnXprDictionary import FnXprDictionary


class XVariable(FnXprDictionaryRecord):
    """CHIF variable.

    tags[0]: variable type
    args[0]: index of symbol in xd
    """

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        FnXprDictionaryRecord.__init__(self, xd, ixval)

    @property
    def symbol(self) -> XSymbol:
        return self.xd.symbol(self.args[0])

    @property
    def name(self) -> str:
        return self.symbol.name

    @property
    def seqnr(self) -> int:
        return self.symbol.seqnr

    @property
    def type(self) -> str:
        return self.tags[0]

    @property
    def is_tmp(self) -> bool:
        return (self.seqnr == -1)

    @property
    def is_register_variable(self) -> bool:
        return self.has_denotation() and self.denotation.is_register_variable

    @property
    def is_initial_register_value(self) -> bool:
        return (
            self.has_denotation()
            and self.denotation.is_auxiliary_variable
            and self.denotation.auxvar.is_initial_register_value)

    def initial_register_value_register(self) -> Register:
        if self.is_initial_register_value:
            return self.denotation.auxvar.register
        raise UF.CHBError("Variable is not an initial register value")

    @property
    def is_memory_variable(self) -> bool:
        return self.has_denotation() and self.denotation.is_memory_variable

    @property
    def is_auxiliary_variable(self) -> bool:
        return self.has_denotation() and self.denotation.is_auxiliary_variable

    def has_denotation(self) -> bool:
        return self.seqnr > 0

    @property
    def denotation(self) -> VAssemblyVariable:
        if self.has_denotation():
            return self.vd.assembly_variable_denotation(self.seqnr)
        else:
            raise UF.CHBError("Variable " + self.name + " does not have denotation")

    @property
    def is_stack_argument(self) -> bool:
        return (self.has_denotation() and self.denotation.is_stack_argument)

    @property
    def is_argument_value(self) -> bool:
        return (self.has_denotation() and self.denotation.is_argument_value)

    @property
    def is_argument_deref_value(self) -> bool:
        return (self.has_denotation() and self.denotation.is_argument_deref_value)

    def argument_deref_arg_offset(self, inbytes: bool = False) -> Tuple[int, int]:
        if self.is_argument_deref_value:
            return self.denotation.argument_deref_arg_offset(inbytes)
        else:
            raise UF.CHBError(
                "Variable " + self.name + " is not an argument-deref-value")

    @property
    def is_global_value(self) -> bool:
        return (self.has_denotation() and self.denotation.is_global_value)

    @property
    def is_global_variable(self) -> bool:
        return (self.has_denotation()
                and (self.denotation.is_global_variable or self.is_global_value))

    def has_global_variable_base(self) -> bool:
        if self.is_global_variable:
            return True
        elif self.has_denotation():
            return self.denotation.has_global_base
        else:
            return False

    def global_variable_base(self) -> VAssemblyVariable:
        if self.has_global_variable_base():
            avar = self.denotation
            if avar.is_initial_memory_value:
                return avar.auxvar.variable.denotation.global_base()
            else:
                return avar.global_base()
        else:
            raise UF.CHBError(
                "Variable " + self.name + " does not have a global base""")

    def get_global_variables(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        if self.is_global_variable or self.has_global_variable_base():
            result[str(self.global_variable_base())] = 1
        return result

    def has_unknown_memory_base(self) -> bool:
        return (
            self.is_memory_variable
            and self.denotation.has_unknown_memory_base())

    @property
    def is_structured_var(self) -> bool:
        return (self.has_denotation() and self.denotation.is_structured_var)

    def argument_index(self) -> int:
        if self.is_argument_value or self.is_stack_argument:
            return self.denotation.argument_index()
        else:
            raise UF.CHBError("Variable " + self.name + " is not an argument value")

    def to_json_result(self) -> JSONResult:
        if self.has_denotation():
            return self.denotation.to_json_result()
        else:
            content: Dict[str, Any] = {}
            content["temp"] = self.name
            content["txtrep"] = self.name
            return JSONResult("variable", content, "ok")

    def __str__(self) -> str:
        if self.has_denotation():
            if self.denotation.is_bridge_variable:
                return "?"
            elif self.denotation.is_function_return_value:
                return str(self.denotation.auxvar)
            else:
                return self.name
        else:
            return self.name
