# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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

from typing import Dict, List, Tuple, TYPE_CHECKING


if TYPE_CHECKING:
    from chb.app.ASTNode import ASTExpr, ASTLval


arm_registers = [
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8",
    "R9", "R10" "R11", "R12", "SP", "LR", "PC"]


def join_usedefs(usedefs: List[Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
        str, List[Tuple[int, "ASTExpr"]]]:
    if len(usedefs) == 0:
        return {}
    else:
        result: Dict[str, List[Tuple[int, "ASTExpr"]]] = copy.deepcopy(usedefs[0])
        for u in usedefs[1:]:
            for s in u:
                result.setdefault(s, [])
                for (id, expr) in u[s]:
                    if all(r[0] != id for r in result[s]):
                        result[s].append((id, expr))
        return result


def update_usedef_assign(
        usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
        instrid: int,
        kill: str,
        gendef: "ASTExpr") -> Dict[str, List[Tuple[int, "ASTExpr"]]]:
    usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]] = {}
    if kill not in usedefs_e:
        usedefs = copy.deepcopy(usedefs_e)        
        if kill in gendef.use():
            return usedefs
        else:
            usedefs[kill] = [(instrid, gendef)]
            return usedefs

    for v in usedefs_e:
        if v == kill and v in gendef.use():
            pass   # remove from usedefs
        elif v == kill:
            usedefs[v] = [(instrid, gendef)]
        else:
            newdefs: List[Tuple[int, "ASTExpr"]] = []
            for (id, expr) in usedefs_e[v]:
                if kill not in expr.use():
                    newdefs.append((id, expr))
            if len(newdefs) > 0:
                usedefs[v] = newdefs
    return usedefs


def update_usedef_call(
        usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
        kill: List[str]) -> Dict[str, List[Tuple[int, "ASTExpr"]]]:
    usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]] = {}
    for v in usedefs_e:
        if v in kill:
            pass  # remove from usedefs
        else:
            newdefs: List[Tuple[int, "ASTExpr"]] = []
            for (id, expr) in usedefs_e[v]:
                if len(set(kill).intersection(set(expr.use()))) == 0:
                    newdefs.append((id, expr))
            if len(newdefs) > 0:
                usedefs[v] = newdefs
    return usedefs


def storage_records(names: List[str]) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    for name in names:
        rec: Dict[str, str] = {}
        rec["name"] = name
        if name in arm_registers:
            rec["type"] = "register"
        elif name.startswith("gv_"):
            rec["type"] = "global"
            rec["va"] = name[3:]
        elif name.startswith("var"):
            rec["type"] = "stack"
            rec["offset"] = str(int(name[4:]))
        else:
            continue
        result.append(rec)
    return result
