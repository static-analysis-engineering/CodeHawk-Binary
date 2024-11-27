# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

from typing import cast, List, Optional, Tuple, Sequence, TYPE_CHECKING, Union

from chb.app.BDictionary import BDictionary, AsmAddress

from chb.bctypes.BCDictionary import BCDictionary
from chb.bctypes.BCTyp import BCTyp

from chb.invariants.VarInvariantFact import (
    DefUse,
    DefUseHigh,
    FlagReachingDefFact,
    ReachingDefFact,
    VarInvariantFact
)

from chb.invariants.XInterval import XInterval
from chb.invariants.XSymbol import XSymbol
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.Function import Function
    from chb.app.FunctionDictionary import FunctionDictionary
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.FnVarInvDictionary import FnVarInvDictionary
    from chb.invariants.FnXprDictionary import FnXprDictionary
    from chb.invariants.VConstantValueVariable import SSARegisterValue


class InstrXData(IndexedTableValue):

    def __init__(
            self,
            fnd: "FunctionDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._fnd = fnd
        self.expanded = False
        self._ssavals: List[XVariable] = []
        self._vars: List[XVariable] = []
        self._types: List["BCTyp"] = []
        self._xprs: List[XXpr] = []
        self._intervals: List[XInterval] = []
        self._strs: List[str] = []
        self._ints: List[int] = []
        self._reachingdefs: List[Optional[ReachingDefFact]] = []
        self._defuses: List[Optional[DefUse]] = []
        self._defuseshigh: List[Optional[DefUseHigh]] = []
        self._flagreachingdefs: List[Optional[FlagReachingDefFact]] = []

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
    def bcdictionary(self) -> "BCDictionary":
        return self.function.bcd

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
    def is_nop(self) -> bool:
        return len(self.tags) == 1 and self.tags[0] == "nop"

    @property
    def vars(self) -> List[XVariable]:
        if not self.expanded:
            self._expand()
        return self._vars

    @property
    def types(self) -> List["BCTyp"]:
        if not self.expanded:
            self._expand()
        return self._types

    @property
    def ssavals(self) -> List[XVariable]:
        if not self.expanded:
            self._expand()
        return self._ssavals

    def has_ssaval(self, register: str) -> bool:
        for v in self._ssavals:
            if v.is_ssa_register_value:
                ssaval = v.ssa_register_value()
                if str(ssaval.register) == register:
                    return True
        return False

    def get_ssaval(self, register: str) -> "SSARegisterValue":
        for v in self._ssavals:
            if v.is_ssa_register_value:
                ssaval = v.ssa_register_value()
                if str(ssaval.register) == register:
                    return ssaval
        raise UF.CHBError(
            "No ssa value found for register " + register)

    def get_var(self, index: int) -> XVariable:
        if index < len(self.vars):
            return self.vars[index]
        else:
            raise UF.CHBError(
                "xdata: var-index out-of-bound: "
                + str(index)
                + " (length is "
                + str(len(self.vars))
                + ")")

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
    def reachingdefs(self) -> List[Optional[ReachingDefFact]]:
        if not self.expanded:
            self._expand()
        return self._reachingdefs

    @property
    def flag_reachingdefs(self) -> List[Optional[FlagReachingDefFact]]:
        if not self.expanded:
            self._expand()
        return self._flagreachingdefs

    @property
    def defuses(self) -> List[Optional[DefUse]]:
        if not self.expanded:
            self._expand()
        return self._defuses

    @property
    def defuseshigh(self) -> List[Optional[DefUseHigh]]:
        if not self.expanded:
            self._expand()
        return self._defuseshigh

    def reachingdeflocs_for(self, var: XVariable) -> Sequence[XSymbol]:
        for rdef in self.reachingdefs:
            if rdef is not None:
                if rdef.variable.seqnr == var.seqnr:
                    return rdef.deflocations
        return []

    def reachingdeflocs_for_s(self, var: str) -> Sequence[XSymbol]:
        for rdef in self.reachingdefs:
            if rdef is not None:
                if str(rdef.variable) == var:
                    return rdef.deflocations
        return []

    def _expand(self) -> None:
        """Expand the arguments based on the argument string in the keys.

        Note: the varinvariant directory is loaded only if the argument
        string contains any of the var-invariant letters (r, d, h, f),
        because not all architectures currently have a varinvariant
        directory. This is the reason it is repeated for every such
        letter; preloading it will cause a crash in systems without.
        """
        self.expanded = True
        if len(self.tags) == 0:
            return
        if self.tags[0] == "nop":
            return
        key = self.tags[0]
        if key.startswith("a:"):
            keyletters = key[2:]
            for (i, c) in enumerate(keyletters):
                arg = self.args[i]
                xd = self.xprdictionary
                bd = self.bdictionary
                bcd = self.bcdictionary
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
                elif c == "t":
                    self._types.append(bcd.typ(arg))
                elif c == "r":
                    varinvd = self.varinvdictionary
                    rdef = varinvd.var_invariant_fact(arg) if arg >= 0 else None
                    rdef = cast(Optional[ReachingDefFact], rdef)
                    self._reachingdefs.append(rdef)
                elif c == "d":
                    varinvd = self.varinvdictionary
                    use = varinvd.var_invariant_fact(arg) if arg >= 0 else None
                    use = cast(Optional[DefUse], use)
                    self._defuses.append(use)
                elif c == "h":
                    varinvd = self.varinvdictionary
                    usehigh = varinvd.var_invariant_fact(arg) if arg > 0 else None
                    usehigh = cast(Optional[DefUseHigh], usehigh)
                    self._defuseshigh.append(usehigh)
                elif c == "f":
                    varinvd = self.varinvdictionary
                    flagrdef = varinvd.var_invariant_fact(arg) if arg >= 0 else None
                    flagrdef = cast(Optional[FlagReachingDefFact], flagrdef)
                    self._flagreachingdefs.append(flagrdef)
                elif c == "c":
                    self._ssavals.append(xd.variable(arg))
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
        elif len(self.tags) >= 2 and self.tags[1] == "call":
            return True
        else:
            return False

    @property
    def is_bx_call(self) -> bool:
        return "bx-call" in self.tags

    def call_target_argument_count(self) -> Optional[int]:
        if len(self.tags) >= 3:
            if self.tags[1] == "call":
                try:
                    return int(self.tags[2])
                except Exception as e:
                    chklogger.logger.warning(
                        "xdata call does not have a valid argument count: %s",
                        self.tags[2])
                    return None

        return None


    def has_inlined_call_target(self) -> bool:
        return len(self.tags) >= 3 and self.tags[2] == "inlined"

    def has_indirect_call_target_exprs(self) -> bool:
        """data format: ["a:...", "u"],[<args> + opx, ropx]"""
        return (len(self.tags) == 2 and self.tags[1] == "u" and len(self.args) > 1)

    def call_target(self, ixd: "InterfaceDictionary") -> "CallTarget":
        if self.has_call_target() and self.is_bx_call:
            return ixd.call_target(self.args[-5])
        elif self.has_call_target():
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

    def has_condition_block_condition(self) -> bool:
        return "TF" in self.tags

    def has_unknown_instruction_condition(self) -> bool:
        return "uc" in self.tags

    def has_base_update(self) -> bool:
        return "bu" in self.tags

    @property
    def is_aggregate_jumptable(self) -> bool:
        return "agg-jt" in self.tags

    def instruction_is_subsumed(self) -> bool:
        """The instruction is subsumed by a larger idiomatic construct.

        Currently this applies only to ARM. Constructs include IfThen
        composites (Thumb-2) or jump tables set up by multiple instructions.
        """

        return "subsumed" in self.tags

    def subsumed_by(self) -> str:
        """Return the address of the subsuming IT instruction."""

        if "subsumed" in self.tags:
            index = self.tags.index("subsumed")
            return self.tags[index + 1]
        else:
            raise UF.CHBError(
                "XData does not have a subsumed-by address: "
                + ", ".join(self.tags))

    def instruction_subsumes(self) -> bool:
        """The instruction is the anchor of a larger idiomatic construct.

        Currently this applies only to ARM. Constructs include IfThne
        composites (Thumb-2) or jump tables.
        """
        return "subsumes" in self.tags

    def subsumes(self) -> List[str]:
        """Return the addresses of the subsumed instructions."""

        if "subsumes" in self.tags:
            index = self.tags.index("subsumes")
            return self.tags[index + 1:]
        else:
            return []

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
        for (i, r) in enumerate(self.reachingdefs):
            lines.append("rdefs[" + str(i) + "] = " + str(r))
        for (i, f) in enumerate(self.flag_reachingdefs):
            lines.append("flagrdefs[" + str(i) + "] = " + str(f))
        for (i, d) in enumerate(self.defuses):
            lines.append("defuses[" + str(i) + "] = " + str(d))
        for (i, du) in enumerate(self.defuseshigh):
            lines.append("defuseshigh[" + str(i) + "] = " + str(du))
        for (i, s) in enumerate(self.ssavals):
            line = "ssa[" + str(i) + "] = " + str(s)
            if s.is_ssa_register_value:
                line += " -> register " + str(s.ssa_register_value().register)
            lines.append(line)
        return "\n".join(lines)
