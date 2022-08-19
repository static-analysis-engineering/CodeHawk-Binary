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
    Any,
    cast,
    Dict,
    List,
    Mapping,
    NewType,
    Optional,
    Sequence,
    Set,
    Tuple,
    TYPE_CHECKING, Union)

from dataclasses import dataclass

from chb.app.CfgBlock import CfgBlock
from chb.app.DerivedGraphSequence import DerivedGraphSequence

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.ASTInterfaceFunction import ASTInterfaceFunction


import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.astinterface.ASTInterfaceFunction import ASTInterfaceFunction



UserNodeID = str # NewType('UserNodeID', str)


class FlowGraph:

    def __init__(
            self,
            nodes: Sequence[UserNodeID],
            edges: Mapping[UserNodeID, Sequence[UserNodeID]],
            start_node: UserNodeID):
        self.nodes = nodes
        self.edges = edges
        self.start_node = start_node
        self._rpo: Dict[UserNodeID, int] = {}
        self._rpo_sorted: List[UserNodeID] = []
        self._edge_flavors: Dict[Tuple[UserNodeID, UserNodeID], str] = {}
        self._revedges: Dict[str, List[str]] = {}
        self._idoms: Dict[UserNodeID, UserNodeID] = {}

        self._compute_dfs() # First DFS computes the reverse postorder list.
        self._compute_dfs() # DFS in RPO order can produce fewer cross edges.
        self._compute_doms()

    def _compute_dfs(self) -> None:
        """Initializes the reverse postorder list."""
        visited = set()
        starttime = {v:0 for v in self.nodes}
        endtime = {v:0 for v in self.nodes}
        vtime = 0

        prev_rpo = self._rpo_sorted
        self._rpo_sorted = []
        self._rpo = {}

        def visit(node: str) -> None:
            nonlocal vtime
            visited.add(node)
            starttime[node] = vtime
            vtime += 1

            # Set iteration order is nondeterministic, so we must sort to ensure
            # determinism.
            successors = sorted(self.post(node))
            if len(prev_rpo) > 0:
                succ_idxs = sorted(prev_rpo.index(x) for x in successors)
                successors = [prev_rpo[i] for i in succ_idxs]

            # Doing DFS a second time, visiting the successors in reverse postorder,
            # helps to avoid unnecessary cross edges.
            for t in successors:
                if t not in visited:
                    self._edge_flavors[(node, t)] = "tree"
                    visit(t)
                else:
                    if endtime[t] == 0: # starttime[t] < starttime[node] and endtime[t] > endtime[node]:
                        self._edge_flavors[(node, t)] = "back"
                    elif starttime[t] > starttime[node]: # and endtime[t] < endtime[node]:
                        self._edge_flavors[(node, t)] = "forward"
                    else: # starttime[t] < starttime[node] and endtime[t] < endtime[node]:
                        self._edge_flavors[(node, t)] = "cross"

            endtime[node] = vtime
            vtime += 1

            self._rpo_sorted.append(node)

        visit(self.start_node)
        self._rpo_sorted.reverse()

    def edge_flavor(self, src: UserNodeID, tgt: UserNodeID) -> str:
        """
        Returns the flavor of the edge ('back', 'forward', 'cross', 'tree') from src to tgt.
        """
        return self._edge_flavors[(src, tgt)]

    @property
    def revedges(self) -> Dict[str, List[str]]:
        if len(self._revedges) == 0:
            for src in self.edges:
                for tgt in self.edges[src]:
                    self._revedges.setdefault(tgt, [])
                    self._revedges[tgt].append(src)
        return self._revedges

    @property
    def rpo_sorted(self) -> List[UserNodeID]:
        """
        Returns a list of the graph's nodes in a reverse postorder.
        """
        return self._rpo_sorted

    @property
    def rpo(self) -> Dict[UserNodeID, int]:
        """
        Returns a mapping from address to index in the reverse postorder.
        """
        if len(self._rpo) == 0:
            self._rpo = {k:i+1 for i, k in enumerate(self.rpo_sorted)}
        return self._rpo

    def post(self, n) -> Set[str]:
        if n in self.edges:
            return set(self.edges[n])
        else:
            return set([])

    def pre(self, n) -> Set[str]:
        if n in self.revedges:
            return set(self.revedges[n])
        else:
            return set([])

    def inverse_with_phantom_exit_node(self) -> 'FlowGraph':
        """
        Returns the inverse of the graph, .
        """
        phantomend = '__' + str(len(self.nodes))
        augedges = self.revedges.copy()
        terminators = [node for node in self.nodes if len(self.post(node)) == 0]
        augedges[phantomend] = terminators
        return FlowGraph(list(self.nodes) + [phantomend], augedges, phantomend)

    def ipostdoms(rrg: 'FlowGraph') -> Dict[UserNodeID, UserNodeID]:
        idoms = rrg.idoms.copy()
        # The start node of the reverse graph is a phantom node that doesn't
        # exist in the original graph.
        del idoms[rrg.start_node]
        return idoms

    def _compute_doms(self) -> None:
        """
        Computes the dominators of each node.

        Implements the algorithm in:
            "A Simple, Fast Dominance Algorithm"
            Keith D. Cooper, Timothy J. Harvey, and Ken Kennedy
            https://www.cs.rice.edu/~keith/EMBED/dom.pdf
        """

        idoms: Dict[UserNodeID, Optional[UserNodeID]] = {n:None for n in self.nodes}

        def intersect(b1: UserNodeID, b2: UserNodeID) -> UserNodeID:
            def idom(n: UserNodeID) -> UserNodeID:
                i = idoms[n]
                assert i is not None # Should always hit start node.
                return cast(UserNodeID, i)

            finger1: UserNodeID = b1
            finger2: UserNodeID = b2
            while finger1 != finger2:
                # The paper describes comparisons on postorder numbers; we're using
                # the reverse postorder numbers, so we need to flip the comparison.
                while self.rpo[finger1] > self.rpo[finger2]:
                    finger1 = idom(finger1)
                while self.rpo[finger2] > self.rpo[finger1]:
                    finger2 = idom(finger2)
            return finger1

        # Initialize the dominators of the start node to be the start node itself.
        idoms[self.start_node] = self.start_node
        changed = True
        while changed:
            changed = False
            for node in self.rpo_sorted:
                if node == self.start_node:
                    continue
                allpreds = list(self.pre(node))
                new_idom = None
                for pred in allpreds:
                    if idoms[pred] is not None:
                        new_idom = pred
                        allpreds.remove(pred) # now it's almost-allpreds...
                        break
                assert new_idom is not None
                for pred in allpreds:
                    if idoms[pred] is not None:
                        new_idom = intersect(pred, new_idom)
                if idoms[node] != new_idom:
                    idoms[node] = new_idom
                    changed = True

        # Validate that no node is missing a dominator, justifying the cast.
        for node in idoms:
            assert idoms[node] is not None
        self._idoms = cast(Dict[UserNodeID, UserNodeID], idoms)

    def idom(self, node: UserNodeID) -> UserNodeID:
        """
        Returns the immediate dominator of the given node.
        """
        return self.idoms[node]

    @property
    def idoms(self) -> Dict[UserNodeID, UserNodeID]:
        """
        Returns a mapping from node to its immediate dominator.
        """
        return self._idoms.copy()

    # Linearly bounded by the depth of the dominator tree
    def dominates(self, node_a: UserNodeID, node_b: UserNodeID) -> bool:
        """
        Returns True if node_a dominates node_b.
        """
        # Self-domination is implicit.
        if node_a == node_b:
            return True

        finger = node_b
        while finger != self.start_node:
            if finger == node_a:
                return True
            finger = self._idoms[finger]
        return False


def normalized_branch(
        astree: ASTInterface,
        astfn: "ASTInterfaceFunction",
        n: str,
        tgtaddr: str,
        ifbranch: AST.ASTStmt,
        elsebranch: AST.ASTStmt) -> AST.ASTBranch:

    def cast_binop(condition: Optional[AST.ASTExpr]) -> Optional[AST.ASTBinaryOp]:
        if condition is None or not condition.is_ast_binary_op:
            return None
        return cast(AST.ASTBinaryOp, condition)

    def inverted_binop(condition: Optional[AST.ASTExpr]) -> Optional[AST.ASTBinaryOp]:
        cond = cast_binop(condition)
        if cond is not None:
            invert = {"ne": "eq", "eq": "ne",
                      "lt": "ge", "ge": "lt",
                      "gt": "le", "le": "gt"}
            if cond.op not in ["lor", "land"]:
                binexpr = astree.mk_binary_expression(invert[cond.op], cond.exp1, cond.exp2)
                return cast(AST.ASTBinaryOp, binexpr)
        return None

    def swapped(condition):
        return astree.mk_branch(condition, elsebranch, ifbranch, tgtaddr)

    astblock = astfn.astblock(n)
    '''
    condition = astblock.ast_condition(astree)
    couqitiou = inverted_binop(condition)
    if couqitiou is not None:
        inverting_eliminates_negation = couqitiou.op == "eq"
        if ifbranch.is_empty() or (inverting_eliminates_negation and not elsebranch.is_empty()):
            return swapped(couqitiou)
    '''
    if ifbranch.is_empty():
        return swapped(astblock.ast_condition(astree, reverse=True))

    else:
        condition = astblock.ast_condition(astree)
        return cast(AST.ASTBranch, astree.mk_branch(
            condition, ifbranch, elsebranch, tgtaddr))


@dataclass
class ControlFlowContext:
    break_to: Optional[str]
    continue_to: Optional[str]
    fallthrough: Optional[str]

    def in_loop(self, x: str) -> 'ControlFlowContext':
        return ControlFlowContext(self.fallthrough, x, x)

    def with_fallthrough(self, f: str) -> 'ControlFlowContext':
        return ControlFlowContext(self.break_to, self.continue_to, f)


class Cfg:

    def __init__(
            self,
            faddr: str,
            xnode: ET.Element) -> None:
        self._faddr = faddr
        self.xnode = xnode
        self._edges: Dict[str, List[str]] = {}
        self._graphseq: Optional[DerivedGraphSequence] = None
        self._flowgraph: Optional[FlowGraph] = None

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

        return self.flowgraph.rpo_sorted

    @property
    def flowgraph(self) -> FlowGraph:
        if self._flowgraph is None:
            self._flowgraph = FlowGraph(self.derived_graph_sequence.nodes,
                                    self.derived_graph_sequence.edges,
                                    self.derived_graph_sequence.graphs[0].nodes[0])
        return self._flowgraph

    def stmt_ast(
            self,
            astfn: "ASTInterfaceFunction",
            astree: ASTInterface,
            blockstmts: Dict[str, AST.ASTStmt]) -> AST.ASTStmt:

        fn = astfn.function

        def expand_domtree() -> Dict[str, List[str]]:
            domtree_adj: Dict[str, List[str]] = dict()
            for node, idom in self.flowgraph._idoms.items():
                # nodes point to those they dominate
                if not idom in domtree_adj:
                    domtree_adj[idom] = []
                domtree_adj[idom].append(node)

            for x in domtree_adj:
                # highest rpo first, since nodeWithin places them in reverse order
                domtree_adj[x].sort(key=lambda x: self.flowgraph.rpo[x], reverse=True)
            return domtree_adj

        def mk_block(stmts: List[AST.ASTStmt]) -> AST.ASTStmt:
            if len(stmts) == 1 and not stmts[0].is_ast_instruction_sequence:
                return stmts[0]
            return astree.mk_block(stmts)

        gotolabels: Set[str] = set() # this is both used and mutated by run_with_gotolabels()
        domtree_adj = expand_domtree()

        def run_with_gotolabels(apply_labels: bool) -> AST.ASTStmt:
            # This beautifully compact algorithm is due to
            #       Norman Ramsey. 2022. Beyond Relooper: Recursive Translation of
            #       Unstructured Control Flow to Structured Control Flow: Functional Pearl.
            #       Proc. ACM Program. Lang. 1, 1 (June 2022)
            # In short, we use the dominator tree, tracking the control flow context
            # of the AST we build, to build an AST which emits every block once and
            # uses jumps or fallthroughs as appropriate. Rather than pre-computing the
            # targets of goto statements, we just record which ones we need,
            # and run the algorithm twice to ensure nodes which need them get labels.
            #
            # Results for irreducible CFGs will be correct but not necessarily pretty.

            def do_tree(x: str, ctx: ControlFlowContext) -> List[AST.ASTStmt]:
                children = domtree_adj[x] if x in domtree_adj else []
                merges = [c for c in children if is_merge_node(c)]
                if is_loop_header(x):
                    return [astree.mk_loop(mk_block(node_within(x, merges, ctx.in_loop(x))))]
                return node_within(x, merges, ctx)

            def do_branch(src: str, tgt: str, ctx: ControlFlowContext) -> List[AST.ASTStmt]:
                if not is_backward(src, tgt) and not is_merge_node(tgt):
                    return do_tree(tgt, ctx)

                if tgt == ctx.fallthrough:
                    return []

                if tgt == ctx.continue_to:
                    return [astree.mk_continue_stmt()]

                if tgt == ctx.break_to:
                    return [astree.mk_break_stmt()]

                gotolabels.add(tgt)
                return [astree.mk_goto_stmt(tgt, tgt)]

            def is_loop_header(x: str) -> bool:
                return any(is_backward(pred, x) for pred in self.flowgraph.pre(x))

            def is_merge_node(x: str) -> bool:
                return len(self.flowgraph.pre(x)) >= 2

            def is_backward(src: str, tgt: str) -> bool:
                # Could compare rpo numbers instead but this seems clearer.
                return self.flowgraph._edge_flavors[(src, tgt)] == "back"

            def labeled_if_needed(x: str) -> AST.ASTStmt:
                xstmt = blockstmts[x]
                if x in gotolabels and apply_labels:
                    xstmt.add_label(x)
                return xstmt

            def node_within(x: str, merges: List[str], ctx: ControlFlowContext) -> List[AST.ASTStmt]:
                if len(merges) >= 1:
                    y_n, ys = merges[0], merges[1:]
                    return node_within(x, ys, ctx.with_fallthrough(y_n)) + do_tree(y_n, ctx)

                succs = self.successors(x)
                nsuccs = len(succs)
                xstmts = [labeled_if_needed(x)]
                if nsuccs == 0:
                    return xstmts # TODO(brk): and return statement?

                if nsuccs == 1:
                    return xstmts + do_branch(x, succs[0], ctx)

                assert nsuccs == 2
                ifbranch = mk_block(do_branch(x, succs[1], ctx))
                elsebranch = mk_block(do_branch(x, succs[0], ctx))
                tgtaddr = succs[1]
                # pcoffset = pcoffset = ( (int(succs[1], 16) - int(succs[0], 16)) - 2)
                return (
                    xstmts
                    + [normalized_branch(
                        astree, astfn, x, tgtaddr, ifbranch, elsebranch)])

            initial = ControlFlowContext(None, None, None)
            return mk_block(do_tree(self.flowgraph.start_node, initial))

        # First run collects the labels; the next run uses them.
        run_with_gotolabels(apply_labels=False)
        return run_with_gotolabels(apply_labels=True)

    def assembly_ast(
            self,
            astfn: "ASTInterfaceFunction",
            astree: ASTInterface) -> AST.ASTStmt:
        blockstmts: Dict[str, AST.ASTStmt] = {}
        for n in self.rpo_sorted_nodes:
            astblock = astfn.astblock(n)
            blocknode = astblock.assembly_ast(astree)
            blockstmts[n] = blocknode

        return self.stmt_ast(astfn, astree, blockstmts)

    def ast(self,
            astfn: "ASTInterfaceFunction",
            astree: ASTInterface) -> AST.ASTStmt:
        blockstmts: Dict[str, AST.ASTStmt] = {}
        for n in self.rpo_sorted_nodes:
            astblock = astfn.astblock(n)
            blocknode = astblock.ast(astree)
            if astblock.has_return:
                instr = astblock.last_instruction
                rv = instr.return_value()
                if rv is not None:
                    astexprs: List[AST.ASTExpr] = XU.xxpr_to_ast_exprs(rv, astree)
                else:
                    astexprs = []
                astexpr = astexprs[0] if len(astexprs) == 1 else None
                rtnstmt = astree.mk_return_stmt(astexpr)
                blocknode = astree.mk_block([blocknode, rtnstmt])
            blockstmts[n] = blocknode

        return self.stmt_ast(astfn, astree, blockstmts)

    def cfg_ast(
            self,
            astfn: "ASTInterfaceFunction",
            astree: ASTInterface) -> AST.ASTStmt:
        """Returns an AST directly based on the CFG."""

        blockstmts: List[AST.ASTStmt] = []
        for b in sorted(self.blocks):
            if b in self.edges:
                successors = self.edges[b]
            else:
                successors = []
            label = astree.mk_label(b)
            blocknode = astfn.astblock(b)
            block = blocknode.assembly_ast(astree)
            succblock: AST.ASTStmt
            if len(successors) == 0:
                succblock = astree.mk_return_stmt(None)
            elif len(successors) == 1:
                succblock = astree.mk_goto_stmt(successors[0], successors[0])
            elif len(successors) == 2:
                falsebranch = astree.mk_goto_stmt(successors[0], successors[0])
                truebranch = astree.mk_goto_stmt(successors[1], successors[1])
                instr = blocknode.last_instruction
                expr = instr.assembly_ast_condition(astree)
                tgtaddr = successors[1]
                succblock = astree.mk_branch(
                    expr, truebranch, falsebranch, tgtaddr)
            else:
                cases: List[AST.ASTStmt] = []
                instr = blocknode.last_instruction
                for s in successors:
                    casexpr = instr.ast_case_expression(s, astree)
                    caselabel = astree.mk_case_label(casexpr)
                    dst = astree.mk_goto_stmt(s, s, labels=[caselabel])
                    cases.append(dst)
                succblock = astree.mk_block(cases)
            bblock = astree.mk_block([block, succblock], labels=[label])
            blockstmts.append(bblock)
        return astree.mk_block(blockstmts)

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
