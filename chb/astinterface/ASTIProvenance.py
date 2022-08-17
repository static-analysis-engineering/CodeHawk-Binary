# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Provenance data structure to provide ast meta data."""

from typing import Dict, List, Optional, TYPE_CHECKING

import chb.ast.ASTNode as AST

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.invariants.VarInvariantFact import VarInvariantFact


class ASTIProvenance:

    def __init__(self):
        self._instr_mapping: Dict[int, List[int]] = {}  # hl_instr -> ll_instrs
        self._expr_mapping: Dict[int, int] = {}   # hl_expr -> ll_expr
        self._lval_mapping: Dict[int, int] = {}   # hl_lval -> ll_lval
        self._expr_rdefs: Dict[int, List["VarInvariantFact"]] = {}
        self._flag_expr_rdefs: Dict[int, List["VarInvariantFact"]] = {}
        self._lval_defuses: Dict[int, "VarInvariantFact"] = {}
        self._lval_defuses_high: Dict[int, "VarInvariantFact"] = {}
        self._instr_addresses: Dict[int, List[str]] = {}  # instr -> hex-address
        self._condition_addresses: Dict[int, List[str]] = {}  # expr -> hex-address
        self._instructions: Dict[int, AST.ASTInstruction] = {}
        self._expressions: Dict[int, AST.ASTExpr] = {}
        self._lvals: Dict[int, AST.ASTLval] = {}

    @property
    def instruction_mapping(self) -> Dict[int, List[int]]:
        return self._instr_mapping

    @property
    def expression_mapping(self) -> Dict[int, int]:
        return self._expr_mapping

    @property
    def expressions_mapped(self) -> str:
        lines: List[str] = []
        for (hl_id, ll_id) in sorted(self.expression_mapping.items()):
            hl_expr = self.expressions[hl_id]
            ll_expr = self.expressions[ll_id]
            lines.append(
                "("
                + str(hl_expr.exprid).rjust(3)
                + ")  "
                + str(hl_expr).ljust(28)
                + "  --->  ("
                + str(ll_expr.exprid).rjust(3)
                + ")  "
                + str(ll_expr))
        return "\n".join(lines)

    @property
    def instruction_addresses(self) -> Dict[int, List[str]]:
        return self._instr_addresses

    @property
    def condition_addresses(self) -> Dict[int, List[str]]:
        return self._condition_addresses

    @property
    def instructions(self) -> Dict[int, AST.ASTInstruction]:
        return self._instructions

    @property
    def expressions(self) -> Dict[int, AST.ASTExpr]:
        return self._expressions

    @property
    def expr_rdefs(self) -> Dict[int, List["VarInvariantFact"]]:
        return self._expr_rdefs

    @property
    def flag_expr_rdefs(self) -> Dict[int, List["VarInvariantFact"]]:
        return self._flag_expr_rdefs

    @property
    def lval_defuses(self) -> Dict[int, "VarInvariantFact"]:
        return self._lval_defuses

    @property
    def lval_defuses_high(self) -> Dict[int, "VarInvariantFact"]:
        return self._lval_defuses_high

    def add_instr_mapping(
            self,
            hl_instr: AST.ASTInstruction,
            ll_instr: AST.ASTInstruction) -> None:
        self._instr_mapping.setdefault(hl_instr.instrid, [])
        if not ll_instr.instrid in self.instruction_mapping:
            self.instruction_mapping[hl_instr.instrid].append(ll_instr.instrid)
        self.add_instruction(hl_instr)
        self.add_instruction(ll_instr)

    def add_expr_mapping(
            self,
            hl_expr: AST.ASTExpr,
            ll_expr: AST.ASTExpr) -> None:
        self._expr_mapping[hl_expr.exprid] = ll_expr.exprid
        self.add_expr(hl_expr)
        self.add_expr(ll_expr)

    def add_lval_mapping(
            self,
            hl_lval: AST.ASTLval,
            ll_lval: AST.ASTLval) -> None:
        self._lval_mapping[hl_lval.lvalid] = ll_lval.lvalid
        self.add_lval(hl_lval)
        self.add_lval(ll_lval)

    def add_expr_reachingdefs(
            self,
            expr: AST.ASTExpr,
            reachingdefs: List["VarInvariantFact"]) -> None:
        if len(reachingdefs) > 0:
            self._expr_rdefs[expr.exprid] = reachingdefs
            self.add_expr(expr)

    def add_flag_expr_reachingdefs(
            self,
            expr: AST.ASTExpr,
            flagreachingdefs: List["VarInvariantFact"]) -> None:
        if len(flagreachingdefs) > 0:
            self._flag_expr_rdefs[expr.exprid] = flagreachingdefs
            self.add_expr(expr)

    def add_lval_defuses(
            self,
            lval: AST.ASTLval,
            uses: Optional["VarInvariantFact"]) -> None:
        if uses is not None:
            self._lval_defuses[lval.lvalid] = uses
            self.add_lval(lval)

    def add_lval_defuses_high(
            self,
            lval: AST.ASTLval,
            useshigh: Optional["VarInvariantFact"]) -> None:
        if useshigh is not None:
            self._lval_defuses_high[lval.lvalid] = useshigh
            self.add_lval(lval)

    def add_instr_address(
            self,
            instr: AST.ASTInstruction,
            addresses: List[str]) -> None:
        self._instr_addresses[instr.instrid] =  addresses
        self.add_instruction(instr)

    def add_condition_address(
            self,
            expr: AST.ASTExpr,
            addresses: List[str]) -> None:
        self._condition_addresses[expr.exprid] = addresses
        self.add_expr(expr)

    def add_instruction(self, instr: AST.ASTInstruction) -> None:
        instrid = instr.instrid
        if not instrid in self._instructions:
            self._instructions[instrid] = instr

    def add_expr(self, expr: AST.ASTExpr) -> None:
        exprid = expr.exprid
        if not exprid in self._expressions:
            self._expressions[exprid] = expr

    def add_lval(self, lval: AST.ASTLval) -> None:
        lvalid = lval.lvalid
        if not lvalid in self._lvals:
            self._lvals[lvalid] = lval

    def has_instruction_mapped(self, instrid: int) -> bool:
        return instrid in self.instruction_mapping

    def get_instructions_mapped(self, instrid: int) -> List[AST.ASTInstruction]:
        if self.has_instruction_mapped(instrid):
            mapped_ids = self.instruction_mapping[instrid]
            return [self.instructions[id] for id in mapped_ids]
        else:
            raise UF.CHBError(
                "Instruction with id " + str(instrid) + " not found")

    def has_expression_mapped(self, exprid: int) -> bool:
        return exprid in self.expression_mapping

    def get_expression_mapped(self, exprid: int) -> AST.ASTExpr:
        if self.has_expression_mapped(exprid):
            mapped_id = self.expression_mapping[exprid]
            return self.expressions[mapped_id]
        else:
            raise UF.CHBError(
                "Expression with id " + str(exprid) + " not found")

    def has_instruction_address(self, instrid: int) -> bool:
        return instrid in self.instruction_addresses

    def get_instruction_address(self, instrid: int) -> List[str]:
        if self.has_instruction_address(instrid):
            return self.instruction_addresses[instrid]
        else:
            raise UF.CHBError(
                "No address found for instruction with id " + str(instrid))

    def has_condition_address(self, exprid: int) -> bool:
        return exprid in self.condition_addresses

    def get_condition_address(self, exprid: int) -> List[str]:
        if self.has_condition_address(exprid):
            return self.condition_addresses[exprid]
        else:
            raise UF.CHBError(
                "No address found for condition with id " + str(exprid))

    def has_lval_defuse(self, lvalid: int) -> bool:
        return lvalid in self.lval_defuses

    def get_lval_defuse(self, lvalid: int) -> "VarInvariantFact":
        if self.has_lval_defuse(lvalid):
            return self.lval_defuses[lvalid]
        else:
            raise UF.CHBError(
                "No defuse found for lval with id " + str(lvalid))

    def has_lval_defuse_high(self, lvalid: int) -> bool:
        return lvalid in self.lval_defuses_high

    def get_lval_defuse_high(self, lvalid: int) -> "VarInvariantFact":
        if self.has_lval_defuse_high(lvalid):
            return self.lval_defuses_high[lvalid]
        else:
            raise UF.CHBError(
                "No defuse-high found for lval with id " + str(lvalid))

    def has_reaching_defs(self, exprid: int) -> bool:
        return exprid in self.expr_rdefs

    def get_reaching_defs(self, exprid: int) -> List["VarInvariantFact"]:
        if self.has_reaching_defs(exprid):
            return self.expr_rdefs[exprid]
        else:
            raise UF.CHBError(
                "No reaching def found for expr with id " + str(exprid))

    def has_flag_reaching_defs(self, exprid: int) -> bool:
        return exprid in self.flag_expr_rdefs

    def get_flag_reaching_defs(self, exprid: int) -> List["VarInvariantFact"]:
        if self.has_flag_reaching_defs(exprid):
            return self.flag_expr_rdefs[exprid]
        else:
            raise UF.CHBError(
                "No flag reaching def found for expr with id " + str(exprid))
