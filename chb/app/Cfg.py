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
"""Abstract superclass of control flow graph.

Subclasses:
  - ARMCfg
  - MIPSCfg
"""

import xml.etree.ElementTree as ET

from typing import (
    Any, cast, Dict, List, Mapping, NewType, Optional, Sequence, Set, Tuple, TYPE_CHECKING, Union)

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree, VariableNamesRec

import chb.app.ASTNode as AST

from chb.app.CfgBlock import CfgBlock
from chb.app.DerivedGraphSequence import DerivedGraphSequence

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.Function import Function


class Cfg:

    def __init__(
            self,
            faddr: str,
            xnode: ET.Element) -> None:
        self._faddr = faddr
        self.xnode = xnode
        self._edges: Dict[str, List[str]] = {}
        self._graphseq: Optional[DerivedGraphSequence] = None

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def blocks(self) -> Mapping[str, CfgBlock]:
        raise UF.CHBError("Property blocks not implemented for Cfg")

    @property
    def edges(self) -> Mapping[str, Sequence[str]]:
        if len(self._edges) == 0:
            xedges = self.xnode.find("edges")
            if xedges is None:
                raise UF.CHBError("Edges are missing from cfg xml")
            for e in xedges.findall("e"):
                src = e.get("src")
                if src is None:
                    raise UF.CHBError("Src address is missing from cfg")
                tgt = e.get("tgt")
                if tgt is None:
                    raise UF.CHBError("Tgt address is missing from cfg")
                self._edges.setdefault(src, [])
                self._edges[src].append(tgt)
        return self._edges

    def modify_edges(
            self,
            remove: List[Tuple[str, str]],
            add: List[Tuple[str, str]]) -> None:
        for (src, tgt) in remove:
            for (s, tl) in self.edges.items():
                if s == src:
                    if tgt in tl:
                        tgtlist: List[str] = [x for x in tl]
                        tgtlist.remove(tgt)
                        self._edges[src] = tgtlist
        for (src, tgt) in add:
            for (s, tl) in self.edges.items():
                if s == src:
                    if tgt not in tl:
                        tgtlist = [x for x in tl]
                        tgtlist.append(tgt)
                        self._edges[src] = tgtlist

    @property
    def edges_as_set(self) -> Set[Tuple[str, str]]:
        result: Set[Tuple[str, str]] = set([])
        for src in self.edges:
            for dst in self.edges[src]:
                result.add((src, dst))
        return result

    @property
    def derived_graph_sequence(self) -> DerivedGraphSequence:
        if self._graphseq is None:
            nodes = list(self.blocks.keys())
            self._graphseq = DerivedGraphSequence(self.faddr, nodes, self.edges)
        return self._graphseq

    @property
    def is_reducible(self) -> bool:
        return self.derived_graph_sequence.is_reducible

    @property
    def rpo_sorted_nodes(self) -> List[str]:
        """Return a list of block addresses in reverse postorder."""

        if self.is_reducible:
            return self.derived_graph_sequence.rpo_sorted_nodes
        else:
            return []

    def stmt_ast(
            self,
            fn: "Function",
            astree: AbstractSyntaxTree,
            blockstmts: Dict[str, AST.ASTStmt]) -> AST.ASTNode:
        twowayconds = self.derived_graph_sequence.two_way_conditionals()

        def construct(
                n: str,
                follow: Optional[str],
                result: List[AST.ASTStmt]) -> AST.ASTStmt:
            if follow and n == follow:
                return astree.mk_block(result)
            elif len(self.successors(n)) == 0:
                return astree.mk_block(result + [blockstmts[n]])
            elif len(self.successors(n)) == 1:
                return construct(
                    self.successors(n)[0], follow, result + [blockstmts[n]])
            elif len(self.successors(n)) == 2:
                if n in twowayconds:
                    follownode: Optional[str] = twowayconds[n]
                else:
                    follownode = None
                ifbranch = construct(self.successors(n)[1], follownode, [])
                elsebranch = construct(self.successors(n)[0], follownode, [])
                pcoffset = (
                    (int(self.successors(n)[1], 16)
                     - int(self.successors(n)[0], 16))
                    - 2)
                if ifbranch.is_empty():
                    condition = fn.blocks[n].assembly_ast_condition(
                        astree, reverse=True)
                    bstmt = astree.mk_branch(
                        condition, elsebranch, ifbranch, pcoffset)
                else:
                    condition = fn.blocks[n].assembly_ast_condition(astree)
                    if (
                            (not elsebranch.is_empty())
                            and condition
                            and condition.is_ast_binary_op):
                        cond = cast(AST.ASTBinaryOp, condition)
                        if cond.op in ["neq", "ne"]:
                            condition = astree.mk_binary_op(
                                "eq", cond.exp1, cond.exp2)
                            bstmt = astree.mk_branch(
                                condition, elsebranch, ifbranch, pcoffset)
                        else:
                            bstmt = astree.mk_branch(
                                condition, ifbranch, elsebranch, pcoffset)
                    else:
                        bstmt = astree.mk_branch(
                            condition, ifbranch, elsebranch, pcoffset)
                branchinstr = fn.blocks[n].last_instruction
                astree.add_instruction_span(
                    bstmt.stmtid, branchinstr.iaddr, branchinstr.bytestring)
                if follownode:
                    return construct(
                        follownode, follow, result + [blockstmts[n], bstmt])
                else:
                    return astree.mk_block(result + [blockstmts[n], bstmt])
            else:
                raise UF.CHBError("Multi branch for " + n)

        return construct(self.faddr, None, [])

    def assembly_ast(
            self,
            fn: "Function",
            astree: AbstractSyntaxTree) -> AST.ASTNode:
        blockstmts: Dict[str, AST.ASTStmt] = {}
        for n in self.rpo_sorted_nodes:
            blocknode = fn.blocks[n].assembly_ast(astree)
            blockstmts[n] = blocknode

        return self.stmt_ast(fn, astree, blockstmts)

    def ast(self,
            fn: "Function",
            astree: AbstractSyntaxTree) -> AST.ASTNode:
        blockstmts: Dict[str, AST.ASTStmt] = {}
        for n in self.rpo_sorted_nodes:
            blocknode = fn.blocks[n].ast(astree)
            if fn.blocks[n].has_return:
                instr = fn.blocks[n].last_instruction
                rv = instr.return_value()
                if rv is not None:
                    astexprs: List[AST.ASTExpr] = XU.xxpr_to_ast_exprs(rv, astree)
                else:
                    astexprs = []
                astexpr = astexprs[0] if len(astexprs) == 1 else None
                rtnstmt = astree.mk_return_stmt(astexpr)
                blocknode = astree.mk_block([blocknode, rtnstmt])
            blockstmts[n] = blocknode

        return self.stmt_ast(fn, astree, blockstmts)

    def max_loop_level(self) -> int:
        return max([len(self.blocks[b].looplevels) for b in self.blocks])

    def has_loop_level(self, baddr: str) -> bool:
        if baddr in self.blocks:
            return len(self.blocks[baddr].looplevels) > 0
        else:
            return False

    def has_loops(self) -> bool:
        return self.max_loop_level() > 0

    def loop_levels(self, baddr: str) -> Sequence[str]:
        if baddr in self.blocks:
            return self.blocks[baddr].looplevels
        else:
            raise UF.CHBError("Blockaddress " + baddr + " not found in cfg")

    def successors(self, src: str) -> Sequence[str]:
        """Addresses of the successor basic blocks.

        For an if-then-else branch the else branch is the first successor.
        """
        if src in self._edges:
            return self._edges[src]
        else:
            return []

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Basic blocks: ")
        for b in self.blocks:
            lines.append(str(b))
        lines.append("\nEdges: ")
        for e in self.edges:
            lines.append(e.ljust(6) + "  [" + ", ".join(self.edges[e]) + "]")
        return "\n".join(lines)
