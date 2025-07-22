# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs LLC
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
import xml.etree.ElementTree as ET

from typing import cast, Dict, List, Optional, Set, TYPE_CHECKING

import chb.bctypes.TypeConstraint as TC

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess


class RegisterParamConstraints:

    def __init__(self, reg: str) -> None:
        self._reg = reg
        self._capabilities: List[List[TC.TypeCapLabel]] = []

    @property
    def capabilities(self) -> List[List[TC.TypeCapLabel]]:
        return self._capabilities

    @property
    def register(self) -> str:
        return self._reg

    def add_capabilities(self, labels: List[TC.TypeCapLabel]) -> None:
        result: List[List[TC.TypeCapLabel]] = []
        labstr = ".".join(str(l) for l in labels)
        for caplist in self.capabilities:
            capstr = ".".join(str(l) for l in caplist)
            if labstr == capstr:
                return
            elif len(labstr) == len(capstr):
                result.append(caplist)
            elif len(labstr) < len(capstr):
                if capstr.find(labstr) == 0:
                    return
                else:
                    result.append(caplist)
            else:
                if labstr.find(capstr) == 0:
                    continue
                else:
                    result.append(caplist)
        result.append(labels)
        self._capabilities = result

    def has_dereference(self) -> bool:
        for caps in self.capabilities:
            if len(caps) > 0:
                if caps[0].is_load or caps[0].is_store:
                    return True
        else:
            return False

    def api_signature(self) -> str:
        if self.has_dereference():
            return "void *" + "param_" + str(self.register)
        else:
            return "int " + "param_" + self.register

    def __str__(self) -> str:
        lines: List[str] = []
        for cap in self.capabilities:
            lines.append("    " + ".".join(str(c) for c in cap))
        return "\n".join(lines)


class FunctionTypeConstraints:

    def __init__(self, addr: str) -> None:
        self._addr = addr
        self._subtype_constraints: List[TC.SubTypeConstraint] = []
        self._var_constraints: List[TC.TypeVariableConstraint] = []
        self._zerocheck_constraints: List[TC.ZeroCheckTypeConstraint] = []
        self._fn_typevars: List[TC.TypeVariable] = []
        self._register_param_constraints: Dict[str, RegisterParamConstraints] = {}

    @property
    def faddr(self) -> str:
        return self._addr

    @property
    def subtype_constraints(self) -> List[TC.SubTypeConstraint]:
        return self._subtype_constraints

    @property
    def var_constraints(self) -> List[TC.TypeVariableConstraint]:
        return self._var_constraints

    @property
    def zerocheck_constraints(self) -> List[TC.ZeroCheckTypeConstraint]:
        return self._zerocheck_constraints

    @property
    def fn_type_variables(self) -> List[TC.TypeVariable]:
        if len(self._fn_typevars) == 0:
            result: Dict[int, TC.TypeVariable] = {}
            for sc in self.subtype_constraints:
                for tv in sc.typevars:
                    if tv.basevar.addr == self.faddr:
                        result[tv.index] = tv
            for vc in self.var_constraints:
                result[vc.typevar.index] = vc.typevar
            for zc in self.zerocheck_constraints:
                result[zc.typevar.index] = zc.typevar
            self._fn_typevars = list(result.values())
        return self._fn_typevars

    @property
    def register_param_constraints(self) -> Dict[str, RegisterParamConstraints]:
        if len(self._register_param_constraints) == 0:
            for typevar in self.fn_type_variables:
                caps = typevar.capabilities
                if len(caps) == 0:
                    continue
                if caps[0].is_reg_param:
                    reg = str(cast(TC.TypeCapLabelFRegParameter, caps[0]).register)
                    self._register_param_constraints.setdefault(
                        reg, RegisterParamConstraints(reg))
                    self._register_param_constraints[reg].add_capabilities(caps[1:])
        return self._register_param_constraints

    def add_subtype_constraint(self, c: TC.SubTypeConstraint) -> None:
        self._subtype_constraints.append(c)

    def add_var_constraint(self, c: TC.TypeVariableConstraint) -> None:
        self._var_constraints.append(c)

    def add_zerocheck_constraint(self, c: TC.ZeroCheckTypeConstraint) -> None:
        self._zerocheck_constraints.append(c)

    def api_signature(self, regs: List[str]) -> str:
        params = sorted(self.register_param_constraints.keys())
        if len(params) > 0:
            parhi = str(params[-1])
            api_params: List[str] = []
            for r in regs:
                api_params.append(r)
                if r == parhi:
                    break
            api_sigs: List[str] = []
            for r in api_params:
                if r in self.register_param_constraints:
                    api_sigs.append(
                        self.register_param_constraints[r].api_signature())
                else:
                    api_sigs.append("int " + "param_" + r)
            return "int sub_" + self.faddr[2:] + "(" + ", ".join(api_sigs) + ");"
        else:
            return "int sub_" + self.faddr[2:] + "();"


    def __str__(self) -> str:
        lines: List[str] = []
        if len(self.subtype_constraints) > 0:
            lines.append("\nSubtype constraints")
            for sc in self.subtype_constraints:
                lines.append("  " + str(sc))
        if len(self.var_constraints) > 0:
            lines.append("\nVAR constraints")
            for vc in self.var_constraints:
                lines.append("  " + str(vc))
        if len(self.zerocheck_constraints) > 0:
            lines.append("\nZeroCheck constraints")
            for zc in self.zerocheck_constraints:
                lines.append("  " + str(zc))

        if len(self.fn_type_variables) > 0:
            lines.append("\nType Variables")
            for tv in self.fn_type_variables:
                lines.append("  " + str(tv))

        if len(self.register_param_constraints) > 0:
            lines.append("\nParameters")
            for (reg, regparam) in sorted(self.register_param_constraints.items()):
                lines.append("  " + reg)
                lines.append(str(regparam))

        lines.append("\n Signature: " + self.api_signature(["R0", "R1", "R2", "R3"]))
        return "\n".join(lines)


class FunctionRegisterConstraints:

    def __init__(self, faddr: str) -> None:
        self._faddr = faddr
        self._var_constraints: List[TC.TypeVariableConstraint] = []

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def var_constraints(self) -> List[TC.TypeVariableConstraint]:
        return self._var_constraints

    def add_var_constraint(self, c: TC.TypeVariableConstraint) -> None:
        self._var_constraints.append(c)

    def __str__(self) -> str:
        lines: List[str] = []
        if len(self.var_constraints) > 0:
            lines.append("\nVAR constraints")
            for vc in self.var_constraints:
                lines.append("  " + str(vc))
        return "\n".join(lines)


class TypingRule:

    def __init__(self, tcstore: "TypeConstraintStore", xr: ET.Element) -> None:
        self._tcstore = tcstore
        self._xr = xr

    @property
    def tcstore(self) -> "TypeConstraintStore":
        return self._tcstore

    @property
    def app(self) -> "AppAccess":
        return self.tcstore.app

    @property
    def iaddr(self) -> str:
        return self._xr.get("loc", "0x0")

    @property
    def rulename(self) -> str:
        return self._xr.get("rule", "?")

    @property
    def typeconstraint(self) -> TC.TypeConstraint:
        ix = self._xr.get("tc-ix")
        if ix is not None:
            return self.app.tcdictionary.type_constraint(int(ix))
        else:
            raise UF.CHBError("Type constraint without tc index")

    def __str__(self) -> str:
        ix = self._xr.get("tc-ix")
        return self.rulename + " " + str(ix) + ":" + str(self.typeconstraint)


class TypeConstraintStore:
    """Global store for type constraints.

    Note: The use of this object is currently somewhat conflicted. It was
    originally intended for global use, to recover function signatures for
    an entire binary. More recently, however, it has been mainly used to
    perform type construction for all local variables (registers and stack)
    within individual functions to support lifting. This latest use in its
    present form does not scale to an entire binary. For now the scaling
    issue is solved by resetting the store after each function, which
    essentially means that the store, when saved, only holds the constraints
    for a single function (the latest processed).
    """

    def __init__(self, app: "AppAccess") -> None:
        self._app = app
        self._constraints: Optional[List[TC.TypeConstraint]] = None
        self._functionconstraints: Dict[str, FunctionTypeConstraints] = {}
        self._functionregconstraints: Dict[str, FunctionRegisterConstraints] = {}
        self._rules_applied: Optional[Dict[str, Dict[str, List[TypingRule]]]] = None

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def rules_applied(self) -> Dict[str, Dict[str, List[TypingRule]]]:
        if self._rules_applied is None:
            self._rules_applied = {}
            tcstore = UF.get_typeconstraint_store_xnode(
                self.app.path, self.app.filename)
            if tcstore is not None:
                rules = tcstore.find("rules-applied")
                if rules is not None:
                    for xf in rules.findall("function"):
                        faddr = xf.get("faddr", "0x0")
                        self._rules_applied[faddr] = {}
                        for xr in xf.findall("rule"):
                            rule = TypingRule(self, xr)
                            self._rules_applied[faddr].setdefault(rule.iaddr, [])
                            self._rules_applied[faddr][rule.iaddr].append(rule)

        return self._rules_applied

    def rules_applied_to_instruction(
            self, faddr: str, iaddr: str) -> List[TypingRule]:
        result: List[TypingRule] = []
        if faddr in self.rules_applied:
            if iaddr in self.rules_applied[faddr]:
                for r in self.rules_applied[faddr][iaddr]:
                    if r.typeconstraint.is_var_constraint:
                        continue
                    result.append(r)
        return result

    @property
    def constraints(self) -> List[TC.TypeConstraint]:
        if self._constraints is None:
            self._constraints = self.app.tcdictionary.type_constraints()
        return self._constraints

    def add_function_constraints(self, addr: str) -> None:
        self._functionconstraints.setdefault(addr, FunctionTypeConstraints(addr))

    @property
    def function_type_constraints(self) -> Dict[str, FunctionTypeConstraints]:
        if len(self._functionconstraints) == 0:
            for c in self.constraints:
                if c.is_var_constraint:
                    c = cast(TC.TypeVariableConstraint, c)
                    addr = c.typevar.base_addr
                    if c.typevar.is_function:
                        self.add_function_constraints(addr)
                        self._functionconstraints[addr].add_var_constraint(
                            cast(TC.TypeVariableConstraint, c))
                elif c.is_subtype_constraint:
                    c = cast(TC.SubTypeConstraint, c)
                    basevars = c.basevars
                    for bv in c.basevars:
                        if bv.is_function:
                            self.add_function_constraints(bv.addr)
                            self._functionconstraints[bv.addr].add_subtype_constraint(c)
                elif c.is_zerocheck_constraint:
                    c = cast(TC.ZeroCheckTypeConstraint, c)
                    addr = c.typevar.base_addr
                    if c.typevar.is_function:
                        self.add_function_constraints(addr)
                        self._functionconstraints[addr].add_zerocheck_constraint(c)
        return self._functionconstraints

    @property
    def function_reg_constraints(self) -> Dict[str, FunctionRegisterConstraints]:
        if len(self._functionregconstraints) == 0:
            for c in self.constraints:
                if c.is_var_constraint:
                    c = cast(TC.TypeVariableConstraint, c)
                    addr = c.typevar.base_addr
                    if c.typevar.is_register_lhs:
                        self._functionregconstraints.setdefault(addr,
                            FunctionRegisterConstraints(addr))
                        self._functionregconstraints[addr].add_var_constraint(c)
        return self._functionregconstraints

    def signatures(self) -> str:
        lines: List[str] = []
        for (_, fnc) in sorted(self.function_type_constraints.items()):
            lines.append(fnc.api_signature(["R0", "R1", "R2", "R3"]))
        return "\n\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Function type constraints")
        for (addr, fc) in sorted(self.function_type_constraints.items()):
            lines.append("\n\nsub_" + addr)
            lines.append(str(fc))
        lines.append("\nFunction register constraints")
        for (addr, frc) in sorted(self.function_reg_constraints.items()):
            lines.append("\n\nsub_" + addr)
            lines.append(str(frc))
        return "\n".join(lines)
