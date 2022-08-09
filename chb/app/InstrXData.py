# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Provides access to invariants for instruction operands."""

from typing import List, Optional, Tuple, Sequence, TYPE_CHECKING, Union

from chb.app.BDictionary import BDictionary, AsmAddress

from chb.invariants.VarInvariantFact import VarInvariantFact
from chb.invariants.XXpr import XXpr
from chb.invariants.XVariable import XVariable
from chb.invariants.XInterval import XInterval

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.Function import Function
    from chb.app.FunctionDictionary import FunctionDictionary
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.FnVarInvDictionary import FnVarInvDictionary
    from chb.invariants.FnXprDictionary import FnXprDictionary


class InstrXData(IndexedTableValue):

    def __init__(
            self,
            fnd: "FunctionDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._fnd = fnd
        self.expanded = False
        self._vars: List[XVariable] = []
        self._xprs: List[XXpr] = []
        self._intervals: List[XInterval] = []
        self._strs: List[str] = []
        self._ints: List[int] = []
        self._reachingdefs: List[Optional[VarInvariantFact]] = []
        self._defuses: List[Optional[VarInvariantFact]] = []
        self._defuseshigh: List[Optional[VarInvariantFact]] = []

    @property
    def functiondictionary(self) -> "FunctionDictionary":
        return self._fnd

    @property
    def function(self) -> "Function":
        return self.functiondictionary.function

    @property
    def bdictionary(self) -> "BDictionary":
        return self.function.bd

    @property
    def xprdictionary(self) -> "FnXprDictionary":
        return self.function.xprdictionary

    @property
    def vardictionary(self) -> "FnVarDictionary":
        return self.function.vardictionary

    @property
    def varinvdictionary(self) -> "FnVarInvDictionary":
        return self.function.varinvdictionary

    @property
    def vars(self) -> List[XVariable]:
        if not self.expanded:
            self._expand()
        return self._vars

    @property
    def xprs(self) -> List[XXpr]:
        if not self.expanded:
            self._expand()
        return self._xprs

    @property
    def intervals(self) -> List[XInterval]:
        if not self.expanded:
            self._expand()
        return self._intervals

    @property
    def strs(self) -> List[str]:
        if not self.expanded:
            self._expand()
        return self._strs

    @property
    def ints(self) -> List[int]:
        if not self.expanded:
            self._expand()
        return self._ints

    @property
    def reachingdefs(self) -> List[Optional[VarInvariantFact]]:
        if not self.expanded:
            self._expand
        return self._reachingdefs

    @property
    def defuses(self) -> List[Optional[VarInvariantFact]]:
        if not self.expanded:
            self._expand
        return self._defuses

    @property
    def defuseshigh(self) -> List[Optional[VarInvariantFact]]:
        if not self.expanded:
            self._expand
        return self._defuseshigh

    def _expand(self) -> None:
        self.expanded = True
        if len(self.tags) == 0:
            return
        key = self.tags[0]
        if key.startswith("a:"):
            keyletters = key[2:]
            for (i, c) in enumerate(keyletters):
                arg = self.args[i]
                xd = self.xprdictionary
                bd = self.bdictionary
                varinvd = self.varinvdictionary
                if c == "v":
                    self._vars.append(xd.variable(arg))
                elif c == "x":
                    self._xprs.append(xd.xpr(arg))
                elif c == "a":
                    self._xprs.append(xd.xpr(arg))
                elif c == "s":
                    self._strs.append(bd.string(arg))
                elif c == "i":
                    self._intervals.append(xd.interval(arg))
                elif c == "l":
                    self._ints.append(arg)
                elif c == "r":
                    rdef = varinvd.var_invariant_fact(arg) if arg >= 0 else None
                    self._reachingdefs.append(rdef)
                elif c == "d":
                    use = varinvd.var_invariant_fact(arg) if arg >= 0 else None
                    self._defuses.append(use)
                elif c == "h":
                    usehigh = varinvd.var_invariant_fact(arg) if arg > 0 else None
                    self._defuseshigh.append(usehigh)
                else:
                    raise UF.CHBError("Key letter not recognized: " + c)

    @property
    def is_function_argument(self) -> bool:
        return len(self.tags) > 1 and self.tags[1] == "arg"

    @property
    def function_argument_callsite(self) -> AsmAddress:
        if self.is_function_argument:
            return self.bdictionary.address(self.args[2])
        else:
            raise UF.CHBError("Operand is not a function argument")

    def has_call_target(self) -> bool:
        if len(self.tags) == 1:
            key = self.tags[0]
            if key.startswith("a:"):
                keyletters = key[2:]
                return len(self.args) == len(keyletters) + 1
            else:
                return False
        elif len(self.tags) == 2 and self.tags[1] == "call":
            return True
        else:
            return False

    def has_indirect_call_target_exprs(self) -> bool:
        """data format: ["a:...", "u"],[<args> + opx, ropx]"""
        return (len(self.tags) == 2 and self.tags[1] == "u" and len(self.args) > 1)

    def call_target(self, ixd: "InterfaceDictionary") -> "CallTarget":
        if self.has_call_target():
            return ixd.call_target(self.args[-1])
        else:
            raise UF.CHBError(
                "XData does not have a call target\n" + str(self))

    def indirect_call_target_exprs(self) -> Sequence[XXpr]:
        if self.has_indirect_call_target_exprs():
            return [self.xprdictionary.xpr(i) for i in self.args[-2:]]
        else:
            raise UF.CHBError(
                "XData does not have indirect call target expressions\n"
                + str(self))

    def has_branch_conditions(self) -> bool:
        return len(self.tags) > 1 and self.tags[1] == "TF"

    def has_condition_setter(self) -> bool:
        return len(self.tags) == 4 and self.tags[1] == "TF"

    def get_condition_setter(self) -> str:
        if len(self.tags) > 2:
            return self.tags[2]
        else:
            raise UF.CHBError(
                "XData does not have a condition setter")

    def get_condition_setter_bytestring(self) -> str:
        if len(self.tags) > 3:
            return self.tags[3]
        else:
            raise UF.CHBError(
                "XData does not have a condition setter bytestring")

    def get_branch_conditions(self) -> Sequence[XXpr]:
        if self.has_branch_conditions():
            return self.xprs
        else:
            raise UF.CHBError(
                "XData does not have branch conditions: " + str(self))

    def has_instruction_condition(self) -> bool:
        return "ic" in self.tags

    def has_unknown_instruction_condition(self) -> bool:
        return "uc" in self.tags

    def has_base_update(self) -> bool:
        return "bu" in self.tags

    def instruction_is_subsumed(self) -> bool:
        """An instruction may be subsumed as part of an ITE construct (ARM)."""

        return "subsumed" in self.tags

    def has_return_value(self) -> bool:
        return "rv" in self.tags

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("index: " + str(self.index))
        lines.append("tags : " + "[" + ", ".join(self.tags) + "]")
        lines.append("args : " + "[" + ", ".join(str(i) for i in self.args) + "]")
        for (i, v) in enumerate(self.vars):
            lines.append("vars[" + str(i) + "] = " + str(v))
        for (i, x) in enumerate(self.xprs):
            lines.append("xprs[" + str(i) + "] = " + str(x))
        return "\n".join(lines)
