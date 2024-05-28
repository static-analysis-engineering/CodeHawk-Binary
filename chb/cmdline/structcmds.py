# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs, LLC
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
"""Commands related to collecting and classifying structured expressions."""

import argparse
import json
import os

from typing import Any, cast, Dict, List, NoReturn

from chb.api.CallTarget import AppTarget

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.invariants.VAssemblyVariable import VMemoryVariable
from chb.invariants.VConstantValueVariable import VFunctionReturnValue
from chb.invariants.VMemoryBase import VMemoryBase, VMemoryBaseBaseVar
from chb.invariants.VMemoryOffset import VMemoryOffset
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF


class DataStructure:

    def __init__(self, base: str) -> None:
        self._base = base
        self._offsets: Dict[str, Dict[str, int]] = {}   # offset -> fn -> count

    @property
    def base(self) -> str:
        return self._base

    @property
    def offsets(self) -> Dict[str, Dict[str, int]]:
        return self._offsets

    def add_offset(self, fn: str, offset: str) -> None:
        self._offsets.setdefault(offset, {})
        self._offsets[offset].setdefault(fn, 0)
        self._offsets[offset][fn] += 1
        


class StructuredLhs:

    def __init__(self, lhs: XVariable) -> None:
        self._lhs = lhs

    @property
    def lhs(self) -> XVariable:
        return self._lhs

    @property
    def deref_depth(self) -> int:
        return str(self).count("[")

    @property
    def base(self) -> VMemoryBase:
        return cast(VMemoryVariable, self.lhs.denotation).base

    @property
    def offset(self) -> VMemoryOffset:
        return cast(VMemoryVariable, self.lhs.denotation).offset

    def basevar_basename(self, faddr: str) -> str:
        basevar = cast(VMemoryBaseBaseVar, self.base).basevar
        if basevar.is_initial_register_value:
            reg = basevar.initial_register_value_register()
            return "s_fn_" + faddr + "_" + str(reg)
        elif basevar.denotation.is_function_return_value:
            auxvar = cast(VFunctionReturnValue, basevar.denotation.auxvar)
            if auxvar.has_call_target():
                tgt = auxvar.call_target()
                if tgt.is_app_target:
                    name = cast(AppTarget, tgt).name
                    return "s_" + name + "_rv"
        return str(self.base)
        
    def basename(self, faddr: str) -> str:
        if self.base.is_basevar:
            return self.basevar_basename(faddr)
        else:
            return str(self.base)

    def offset_string(self) -> str:
        return str(self.offset)
    
    def __str__(self) -> str:
        return str(self.lhs)


class StructuredRhs:

    def __init__(self, rhs: XXpr) -> None:
        self._rhs = rhs

    @property
    def rhs(self) -> XXpr:
        return self._rhs

    @property
    def deref_depth(self) -> int:
        return str(self).count("[")

    def __str__(self) -> str:
        return str(self.rhs)


class StructuredFunction:

    def __init__(self, faddr: str) -> None:
        self._faddr = faddr
        self._lhss: List[StructuredLhs] = []
        self._rhss: List[StructuredRhs] = []

    def add_lhs(self, lhs: StructuredLhs) -> None:
        self._lhss.append(lhs)

    def add_rhs(self, rhs: StructuredRhs) -> None:
        self._rhss.append(rhs)

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def lhss(self) -> List[StructuredLhs]:
        return self._lhss

    @property
    def rhss(self) -> List[StructuredRhs]:
        return self._rhss

    @property
    def lhs_count(self) -> int:
        return len(self.lhss)

    @property
    def rhs_count(self) -> int:
        return len(self.rhss)

    @property
    def structure_count(self) -> int:
        return self.lhs_count + self.rhs_count

    def max_deref_depth(self) -> int:
        m: int = 0
        for v in self.lhss:
            if v.deref_depth > m:
                m = v.deref_depth
        for x in self.rhss:
            if x.deref_depth > m:
                m = x.deref_depth
        return m    


class StructureClassification:

    def __init__(self) -> None:
        self._functions: Dict[str, StructuredFunction] = {}
        self._lhss: Dict[str, List[StructuredLhs]] = {}
        self._rhss: Dict[str, List[StructuredRhs]] = {}
        self._initrhss: List[XVariable] = []
        self._baselhss: Dict[str, Dict[str, int]] = {}
        self._baserhss: Dict[str, Dict[str, int]] = {}
        self._datastructures: Dict[str, DataStructure] = {}

    def add_function(self, faddr: str) -> None:
        if not faddr in self.functions:
            self._functions[faddr] = StructuredFunction(faddr)

    def add_lhs(self, faddr: str, lhss: List[XVariable]) -> None:
        self.add_function(faddr)
        self._lhss[faddr] = []
        for lhs in lhss:
            slhs = StructuredLhs(lhs)
            self.functions[faddr].add_lhs(slhs)
            self._lhss[faddr].append(slhs)
            if lhs.is_memory_variable:
                base = str(cast(VMemoryVariable, lhs.denotation).base)
                self._baselhss.setdefault(base, {})
                self._baselhss[base].setdefault(str(lhs), 0)
                self._baselhss[base][str(lhs)] += 1
                structbasename = slhs.basename(faddr)
                self._datastructures.setdefault(
                    structbasename, DataStructure(structbasename))
                self._datastructures[structbasename].add_offset(faddr, slhs.offset_string())
            else:
                print("Unexpected type of lhs: " + str(lhs))

    def add_rhs(self, faddr: str, rhss: List[XXpr]) -> None:
        self.add_function(faddr)
        self._rhss[faddr] = []
        for rhs in rhss:
            srhs = StructuredRhs(rhs)
            self.functions[faddr].add_rhs(srhs)
            self._rhss[faddr].append(srhs)
            if rhs.is_var:
                xvar = rhs.variable
                if xvar.is_initial_memory_value:
                    self._initrhss.append(xvar)
                    xvar = xvar.denotation.auxvar.variable
                base = str(cast(VMemoryVariable, xvar.denotation).base)
                self._baserhss.setdefault(base, {})
                self._baserhss[base].setdefault(str(xvar), 0)
                self._baserhss[base][str(xvar)] += 1

    @property
    def functions(self) -> Dict[str, StructuredFunction]:
        return self._functions

    @property
    def lhss(self) -> Dict[str, List[StructuredLhs]]:
        return self._lhss

    @property
    def rhss(self) -> Dict[str, List[StructuredRhs]]:
        return self._rhss

    @property
    def baselhss(self) -> Dict[str, Dict[str, int]]:
        return self._baselhss

    @property
    def baserhss(self) -> Dict[str, Dict[str, int]]:
        return self._baserhss

    @property
    def initrhss(self) -> List[XVariable]:
        return self._initrhss

    @property
    def datastructures(self) -> List[DataStructure]:
        return list(self._datastructures.values())

    @property
    def lhs_count(self) -> int:
        return sum(len(self.lhss[f]) for f in self.lhss)

    @property
    def rhs_count(self) -> int:
        return sum(len(self.rhss[f]) for f in self.rhss)

    def function_depths(self) -> Dict[int, int]:
        result: Dict[int, int] = {}
        for f in self.functions.values():
            maxdepth = f.max_deref_depth()
            result.setdefault(maxdepth, 0)
            result[maxdepth] += 1
        return result

    def baselhss_stats(self) -> str:
        lines: List[str] = []
        for (base, vars) in sorted(self.baselhss.items()):
            lines.append("\n" + base + " (" + str(sum(vars[v] for v in vars)) + ")")
            for (v, c) in sorted(vars.items()):
                lines.append(str(c).rjust(8) + "  " + v)
        return "\n".join(lines)

    def baserhss_stats(self) -> str:
        lines: List[str] = []
        for (base, vars) in sorted(self.baserhss.items()):
            lines.append("\n" + base + " (" + str(sum(vars[v] for v in vars)) + ")")
            for (v, c) in sorted(vars.items()):
                lines.append(str(c).rjust(8) + "  " + v)
        return "\n".join(lines)

    def function_stats(self) -> str:
        lines: List[str] = []
        for (depth, count) in sorted(self.function_depths().items()):
            lines.append(str(depth).rjust(5) + "  " + str(count))
        return "\n".join(lines)
            

def results_structs(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        UC.print_error(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = UC.get_app(path, xfile, xinfo)

    lhsvars = app.get_lhs_variables(lambda v: v.is_structured_var)
    rhsxprs = app.get_rhs_expressions(
        lambda x: x.is_structured_expr and not x.is_compound)

    structures = StructureClassification()

    for (faddr, fvars) in lhsvars.items():
        structures.add_lhs(faddr, fvars)

    for (faddr, fxprs) in rhsxprs.items():
        structures.add_rhs(faddr, fxprs)

    print("Lhs classification")
    print(structures.baselhss_stats())

    print("\nRhs classification")
    print(structures.baserhss_stats())

    print("Functions      : " + str(len(app.functions)))
    print("Functions with derefxpr: " + str(len(structures.functions)))
    print(
        "Deref xprs     : "
        + str(sum(structures.functions[f].structure_count
                  for f in structures.functions)))
    print("Base lhs values: " + str(len(structures.baselhss)))
    print("Base rhs values: " + str(len(structures.baserhss)))

    print("\nFunction depths")
    print(structures.function_stats())

    print("\nFunctions with large structure depth")
    for f in structures.functions.values():
        if f.max_deref_depth() >= 7:
            if app.has_function_name(f.faddr):
                name = f.faddr + " (" + app.function_name(f.faddr) + ")"
            else:
                name = f.faddr
            print(name + ": " + str(f.max_deref_depth()))

    print("\nData structures")
    for d in sorted(structures.datastructures, key=lambda d:d.base):
        print("\n" + d.base)
        for (off, fncounts) in d.offsets.items():
            print("  " + off)
            for (fn, count) in fncounts.items():
                print("    " + fn + ": " + str(count))
        

    exit(0)
        
    
