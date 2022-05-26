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
"""Utilities for AST nodes."""

import copy

from typing import Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING

import chb.util.fileutil as UF


if TYPE_CHECKING:
    from chb.ast.ASTNode import ASTExpr, ASTLval
    from chb.astinterface.ASTIVarInfo import ASTIVarInfo


arm_registers = [
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8",
    "R9", "R10" "R11", "R12", "SP", "LR", "PC"]


def get_arm_arg_loc(bytecounter: int, size: int) -> str:
    index = bytecounter // 4
    rem = bytecounter % 4
    if index < 4:
        if size == 4:
            if rem == 0:
                return "R" + str(index)
            else:
                raise UF.CHBError(
                    "Unexpected alignment in arm argument location")
        else:
            return "R" + str(index) + ":" + str(rem)

    else:
        return "stack:" + str(bytecounter - 16)


def get_mips_arg_loc(bytecounter: int, size: int) -> str:
    index = bytecounter // 4
    rem = bytecounter % 4
    if index < 4:
        if size == 4:
            if rem == 0:
                return "a" + str(index)
            else:
                raise UF.CHBError(
                    "Unexpected alignment in mips argument location")
        else:
            return "a" + str(index) + ":" + str(rem)
    else:
        return "stack:" + str(bytecounter)


def get_arg_loc(callingconvention: str, bytecounter: int, size: int) -> str:
    """Return a string that denotes the location of a given function argument."""

    index = bytecounter // 4
    if index < 0:
        raise Exception(
            "Argument index cannot be smaller than zero: " + str(index))
    if callingconvention == "arm":
        return get_arm_arg_loc(bytecounter, size)
    elif callingconvention == "mips":
        return get_mips_arg_loc(bytecounter, size)
    else:
        return "?"


'''
def storage_records(vinfos: Sequence["ASTIVarInfo"]) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    for vinfo in vinfos:
        rec: Dict[str, str] = {}
        name = vinfo.vname
        if name == "ignored":
            continue
        rec["name"] = name
        if name in arm_registers:
            rec["type"] = "register"
        elif name.startswith("gv_"):
            rec["type"] = "global"
            rec["va"] = name[3:]
        elif name.startswith("var"):
            rec["type"] = "stack"
            rec["offset"] = str(int(name[4:]))
        elif vinfo.is_parameter:
            rec["type"] = "parameter"
            rec["index"] = str(vinfo.parameter)
        elif vinfo.global_address:
            rec["type"] = "global"
            rec["va"] = hex(vinfo.global_address)
        else:
            rec["type"] = "unknown"
        result.append(rec)
    return result
'''


def has_global_denotation(
        varinfos: Sequence["ASTIVarInfo"], gaddr: str) -> Optional["ASTIVarInfo"]:
    return None


'''
    addr = int(gaddr, 16)
    for vinfo in varinfos:
        if (
                vinfo.global_address
                and vinfo.global_address > 0
                and vinfo.vtype
                and len(vinfo.conflicting_types) == 0):
            if addr == vinfo.global_address:
                return vinfo
            elif vinfo.vtype.is_compound:
                bytesize = vinfo.vtype.byte_size()
                structextent = vinfo.global_address + bytesize
                if addr > vinfo.global_address and addr < structextent:
                    return vinfo
    else:
        return None
'''


class UseDef:
    """Holds a mapping from variables to (label * expr) tuples on node entry.

    These definitions are used for replacement, hence only one definition is
    allowed.

    This object is immutable.
    """

    def __init__(
            self,
            defs: Mapping[str, Tuple[int, "ASTLval", "ASTExpr"]]) -> None:
        self._defs = defs

    @property
    def defs(self) -> Mapping[str, Tuple[int, "ASTLval", "ASTExpr"]]:
        return self._defs

    @property
    def variables(self) -> Sequence[str]:
        return list(self.defs.keys())

    def has_name(self, v: str) -> bool:
        return v in self.defs

    def has_stack_variable(self) -> bool:
        return any(v.startswith("localvar_") for v in self.defs)

    def get(self, v: str) -> Tuple[int, "ASTLval", "ASTExpr"]:
        if v in self.defs:
            return self.defs[v]
        else:
            raise Exception("Variable: " + v + " not found in usedef")

    def apply_assign(
            self,
            assembly_xref: int,
            lval: "ASTLval",
            gendef: "ASTExpr") -> "UseDef":

        # print("Apply assign: " + str(lval) + " := " + str(gendef))

        kill = str(lval)

        if not lval.is_variable:        # some protection against aliasing
            return UseDef(self.defs)    # needs to be strengthened

        if kill not in self.defs:
            if kill in gendef.use():             # nothing to add or remove
                return UseDef(self.defs)

        usedefs: Dict[str, Tuple[int, "ASTLval", "ASTExpr"]] = {}
        if kill not in self.defs:
            usedefs[kill] = (assembly_xref, lval, gendef)

        for v in self.defs:
            if v == kill and v in gendef.use():
                pass    # remove from usedefs
            elif v == kill:
                usedefs[v] = (assembly_xref, lval, gendef)    # replace
            elif (
                    kill not in self.defs[v][1].use()
                    and kill not in self.defs[v][2].use()):
                usedefs[v] = self.defs[v]         # keep this def
            else:
                pass   # leave out this def

        return UseDef(usedefs)

    def apply_call(self, kill: Sequence[str]) -> "UseDef":
        usedefs: Dict[str, Tuple[int, "ASTLval", "ASTExpr"]] = {}
        for v in self.defs:
            if v in kill:
                pass   # remove from usedefs
            else:
                for k in kill:
                    if k in self.defs[v][1].use():
                        break         # remove from usedefs
                else:
                    usedefs[v] = self.defs[v]    # keep this def

        return UseDef(usedefs)

    def join(self, other: "UseDef") -> "UseDef":

        # only keep definitions that are shared
        if len(other.defs) == 0 or len(self.defs) == 0:
            return UseDef({})

        newdefs: Dict[str, Tuple[int, "ASTLval", "ASTExpr"]] = {}
        for v in self.defs:
            if v in other.defs:
                if self.defs[v][0] == other.defs[v][0]:
                    newdefs[v] = self.defs[v]

        return UseDef(newdefs)

    def __str__(self) -> str:
        lines: List[str] = []
        for (name, (i, lv, x)) in self.defs.items():
            ctype = str(lv.ctype) + " " if lv.ctype else ""
            lines.append(ctype + name + ": " + str(x))
        return "\n".join(lines)


class InstrUseDef:

    def __init__(self) -> None:
        self._instrdefs: Dict[int, UseDef] = {}

    @property
    def instrdefs(self) -> Dict[int, UseDef]:
        return self._instrdefs

    def has(self, assembly_xref: int) -> bool:
        return assembly_xref in self.instrdefs

    def set(self, assembly_xref: int, usedef: UseDef) -> None:
        self._instrdefs[assembly_xref] = usedef

    def get(self, assembly_xref: int) -> UseDef:
        if assembly_xref in self.instrdefs:
            return self.instrdefs[assembly_xref]
        else:
            raise Exception(
                "Assembly-xref: " + str(assembly_xref) + " not in usedef")
