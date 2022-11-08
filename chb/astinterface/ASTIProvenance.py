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

from typing import cast, Dict, List, Optional, Set, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.ast.ASTProvenance import ASTProvenance

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.invariants.VarInvariantFact import (
        DefUse,
        DefUseHigh,
        FlagReachingDefFact,
        ReachingDefFact,
        VarInvariantFact
    )


class ASTIProvenance:

    def __init__(self) -> None:
        self._instr_mapping: Dict[int, List[int]] = {}  # hl_instr -> ll_instrs
        self._expr_mapping: Dict[int, int] = {}   # hl_expr -> ll_expr
        self._lval_mapping: Dict[int, int] = {}   # hl_lval -> ll_lval
        self._reaching_definitions: Dict[int, List[int]] = {}
        self._flag_reaching_definitions: Dict[int, List[int]] = {}
        self._definitions_used: Dict[int, List[int]] = {}
        self._expr_rdefs: Dict[int, List["ReachingDefFact"]] = {}
        self._flag_expr_rdefs: Dict[int, List["FlagReachingDefFact"]] = {}
        self._lval_defuses: Dict[int, "DefUse"] = {}
        self._lval_defuses_high: Dict[int, "DefUseHigh"] = {}
        self._lval_stores: List[int] = []
        self._instr_addresses: Dict[int, List[str]] = {}  # instr -> hex-address
        self._addr_instructions: Dict[str, List[int]] = {}  # hex-address -> instrs
        self._condition_addresses: Dict[int, List[str]] = {}  # expr -> hex-address
        self._instructions: Dict[int, AST.ASTInstruction] = {}
        self._expressions: Dict[int, AST.ASTExpr] = {}
        self._lvals: Dict[int, AST.ASTLval] = {}
        self._defuses_high_inactivated: Dict[int, Set[str]] = {}

    @property
    def instruction_mapping(self) -> Dict[int, List[int]]:
        return self._instr_mapping

    @property
    def expression_mapping(self) -> Dict[int, int]:
        return self._expr_mapping

    @property
    def lval_mapping(self) -> Dict[int, int]:
        return self._lval_mapping

    @property
    def reaching_definitions(self) -> Dict[int, List[int]]:
        return self._reaching_definitions

    @property
    def flag_reaching_definitions(self) -> Dict[int, List[int]]:
        return self._flag_reaching_definitions

    @property
    def definitions_used(self) -> Dict[int, List[int]]:
        return self._definitions_used

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
    def address_instructions(self) -> Dict[str, List[int]]:
        return self._addr_instructions

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
    def expr_rdefs(self) -> Dict[int, List["ReachingDefFact"]]:
        return self._expr_rdefs

    @property
    def flag_expr_rdefs(self) -> Dict[int, List["FlagReachingDefFact"]]:
        return self._flag_expr_rdefs

    @property
    def lval_defuses(self) -> Dict[int, "DefUse"]:
        return self._lval_defuses

    @property
    def lval_defuses_high(self) -> Dict[int, "DefUseHigh"]:
        return self._lval_defuses_high

    @property
    def defuses_high_inactivated(self) -> Dict[int, Set[str]]:
        return self._defuses_high_inactivated

    @property
    def lval_stores(self) -> List[int]:
        return self._lval_stores

    def add_instr_mapping(
            self,
            hl_instr: AST.ASTInstruction,
            ll_instr: AST.ASTInstruction) -> None:
        self._instr_mapping.setdefault(hl_instr.instrid, [])
        if ll_instr.instrid not in self.instruction_mapping:
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

    def add_reaching_definition(self, exprid: int, instrid: int) -> None:
        self._reaching_definitions.setdefault(exprid, [])
        if instrid not in self.reaching_definitions[exprid]:
            self._reaching_definitions[exprid].append(instrid)

    def add_flag_reaching_definition(self, exprid: int, instrid: int) -> None:
        self._flag_reaching_definitions.setdefault(exprid, [])
        if instrid not in self.flag_reaching_definitions[exprid]:
            self._flag_reaching_definitions[exprid].append(instrid)

    def add_definition_used(self, lvalid: int, instrid: int) -> None:
        self._definitions_used.setdefault(lvalid, [])
        if instrid not in self.definitions_used[lvalid]:
            self._definitions_used[lvalid].append(instrid)

    def add_expr_reachingdefs(
            self,
            expr: AST.ASTExpr,
            reachingdefs: List["ReachingDefFact"]) -> None:
        if len(reachingdefs) > 0:
            self._expr_rdefs[expr.exprid] = reachingdefs
            self.add_expr(expr)

    def add_flag_expr_reachingdefs(
            self,
            expr: AST.ASTExpr,
            flagreachingdefs: List["FlagReachingDefFact"]) -> None:
        if len(flagreachingdefs) > 0:
            self._flag_expr_rdefs[expr.exprid] = flagreachingdefs
            self.add_expr(expr)

    def add_lval_defuses(
            self,
            lval: AST.ASTLval,
            uses: Optional["DefUse"]) -> None:
        if uses is not None:
            self._lval_defuses[lval.lvalid] = uses
            self.add_lval(lval)

    def add_lval_defuses_high(
            self,
            lval: AST.ASTLval,
            useshigh: Optional["DefUseHigh"]) -> None:
        if useshigh is not None:
            self._lval_defuses_high[lval.lvalid] = useshigh
            self.add_lval(lval)

    def inactivate_lval_defuse_high(
            self,
            lvalid: int,
            defuseaddr: str) -> None:
        self._defuses_high_inactivated.setdefault(lvalid, set([]))
        self._defuses_high_inactivated[lvalid].add(defuseaddr)

    def add_lval_store(self, lval: AST.ASTLval) -> None:
        self._lval_stores.append(lval.lvalid)
        self.add_lval(lval)

    def add_instr_address(
            self,
            instr: AST.ASTInstruction,
            addresses: List[str]) -> None:
        self._instr_addresses[instr.instrid] = addresses
        for addr in addresses:
            self._addr_instructions.setdefault(addr, [])
            if instr.instrid not in self.address_instructions[addr]:
                self._addr_instructions[addr].append(instr.instrid)

        self.add_instruction(instr)

    def add_condition_address(
            self,
            expr: AST.ASTExpr,
            addresses: List[str]) -> None:
        self._condition_addresses[expr.exprid] = addresses
        self.add_expr(expr)

    def add_instruction(self, instr: AST.ASTInstruction) -> None:
        instrid = instr.instrid
        if instrid not in self._instructions:
            self._instructions[instrid] = instr

    def add_expr(self, expr: AST.ASTExpr) -> None:
        exprid = expr.exprid
        if exprid not in self._expressions:
            self._expressions[exprid] = expr

    def add_lval(self, lval: AST.ASTLval) -> None:
        lvalid = lval.lvalid
        if lvalid not in self._lvals:
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

    def get_lval_defuse(self, lvalid: int) -> "DefUse":
        if self.has_lval_defuse(lvalid):
            return self.lval_defuses[lvalid]
        else:
            raise UF.CHBError(
                "No defuse found for lval with id " + str(lvalid))

    def has_lval_defuse_high(self, lvalid: int) -> bool:
        return lvalid in self.lval_defuses_high

    def defuses_high_inactivated_for(self, lvalid: int) -> Set[str]:
        if lvalid in self.defuses_high_inactivated:
            return self.defuses_high_inactivated[lvalid]
        else:
            return set([])

    def has_active_lval_defuse_high(self, lvalid: int) -> bool:
        if lvalid in self.lval_defuses_high:
            defuseshigh = self.lval_defuses_high[lvalid]
            locations = [str(x) for x in defuseshigh.uselocations]
            inactivated = self.defuses_high_inactivated_for(lvalid)
            active = set(locations).difference(inactivated)
            return len(active) > 0

        return False

    def has_lval_store(self, lvalid: int) -> bool:
        return lvalid in self.lval_stores

    def get_lval_defuse_high(self, lvalid: int) -> "DefUseHigh":
        if self.has_lval_defuse_high(lvalid):
            return self.lval_defuses_high[lvalid]
        else:
            raise UF.CHBError(
                "No defuse-high found for lval with id " + str(lvalid))

    def has_reaching_defs(self, exprid: int) -> bool:
        return exprid in self.expr_rdefs

    def get_reaching_defs(self, exprid: int) -> List["ReachingDefFact"]:
        if self.has_reaching_defs(exprid):
            return self.expr_rdefs[exprid]
        else:
            raise UF.CHBError(
                "No reaching def found for expr with id " + str(exprid))

    def has_flag_reaching_defs(self, exprid: int) -> bool:
        return exprid in self.flag_expr_rdefs

    def get_flag_reaching_defs(self, exprid: int) -> List["FlagReachingDefFact"]:
        if self.has_flag_reaching_defs(exprid):
            return self.flag_expr_rdefs[exprid]
        else:
            raise UF.CHBError(
                "No flag reaching def found for expr with id " + str(exprid))

    def set_ast_provenance(self, p: ASTProvenance) -> None:
        self.resolve_reaching_defs()
        self.resolve_flag_reaching_defs()
        self.resolve_definitions_used()
        self.resolve_definitions_used_high()
        for (hl, lls) in self.instruction_mapping.items():
            for ll in lls:
                p.add_instruction_mapping(hl, ll)
        for (hl, ll) in self.expression_mapping.items():
            p.add_expression_mapping(hl, ll)
        for (hl, ll) in self.lval_mapping.items():
            p.add_lval_mapping(hl, ll)
        for (xid, rds) in self.reaching_definitions.items():
            p.add_reaching_definitions(xid, rds)
        for (xid, frds) in self.flag_reaching_definitions.items():
            p.add_flag_reaching_definitions(xid, frds)
        for (lvalid, dus) in self.definitions_used.items():
            p.add_definitions_used(lvalid, dus)

    def resolve_reaching_defs(self) -> None:
        for (xid, rds) in self.expr_rdefs.items():
            for rd in rds:
                rd = cast("ReachingDefFact", rd)
                v = str(rd.variable)
                addrs = [str(d) for d in rd.deflocations]
                for addr in addrs:
                    if addr in self.address_instructions:
                        instrids = self.address_instructions[addr]
                        for instrid in instrids:
                            if instrid in self.instructions:
                                instr = self.instructions[instrid]
                                if instr.is_ast_assign:
                                    instr = cast(AST.ASTAssign, instr)
                                    if str(instr.lhs) == v:
                                        self.add_reaching_definition(xid, instrid)

    def resolve_flag_reaching_defs(self) -> None:
        for (xid, frds) in self.flag_expr_rdefs.items():
            for frd in frds:
                frd = cast("FlagReachingDefFact", frd)
                addrs = [str(d) for d in frd.deflocations]
                for addr in addrs:
                    instrids = self.address_instructions[addr]
                    for instrid in instrids:
                        self.add_flag_reaching_definition(xid, instrid)

    def resolve_definitions_used(self) -> None:
        for (lvalid, defuse) in self.lval_defuses.items():
            defuse = cast("DefUse", defuse)
            addrs = [str(u) for u in defuse.uselocations if str(u) != "exit"]
            for addr in addrs:
                if addr in self.address_instructions:
                    instrids = self.address_instructions[addr]
                    for instrid in instrids:
                        self.add_definition_used(lvalid, instrid)
                else:
                    print("  DU: instruction address missing: " + addr)

    def resolve_definitions_used_high(self) -> None:
        for (lvalid, defuse) in self.lval_defuses_high.items():
            defuse = cast("DefUseHigh", defuse)
            addrs = [str(u) for u in defuse.uselocations if str(u) != "exit"]
            for addr in addrs:
                if addr in self.address_instructions:
                    instrids = self.address_instructions[addr]
                    for instrid in instrids:
                        self.add_definition_used(lvalid, instrid)
                else:
                    print("  DH: instruction address missing: " + addr)
