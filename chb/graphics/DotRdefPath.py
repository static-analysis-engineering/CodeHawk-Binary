# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2025  Aarno Labs LLC
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

from typing import Dict, List, Optional, TYPE_CHECKING

import chb.util.fileutil as UF

from chb.util.DotGraph import DotGraph

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.astinterface.ASTInterface import ASTInterface


class DotRdefPath:

    def __init__(
            self,
            graphname: str,
            fn: "Function",
            astree: "ASTInterface",
            path: List[str],
            nodeprefix: str = "",
            replacements: Dict[str, str] = {},
            rdefinstrs: List[str] = [],
            subgraph: bool = False) -> None:

        self._fn = fn
        self._graphname = graphname
        self._astree = astree
        self._path = path
        self._nodeprefix = nodeprefix
        self._subgraph = subgraph
        self._replacements = replacements
        self._rdefinstrs = rdefinstrs
        self._dotgraph = DotGraph(graphname, subgraph=self.subgraph)

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def graphname(self) -> str:
        return self._graphname

    @property
    def astree(self) -> "ASTInterface":
        return self._astree

    @property
    def path(self) -> List[str]:
        return self._path

    @property
    def nodeprefix(self) -> str:
        return self._nodeprefix

    @property
    def subgraph(self) -> bool:
        return self._subgraph

    def pathindex(self, baddr: str) -> int:
        for (i, n) in enumerate(self.path):
            if n == baddr:
                return i
        raise UF.CHBError("Address " + baddr + " not found in path")

    def build(self) -> DotGraph:
        for n in self.path:
            self.add_node(n)

        for i in range(len(self.path) - 1):
            self.add_edge(self.path[i], self.path[i+1])

        if self.init_is_exposed():
            (fvar, _) = self.astree.get_formal_locindices(0)
            btype = fvar.bctyp
            self._dotgraph.add_node(
                self.nodeprefix + "init",
                labeltxt="{ init | " + str(btype) + " " + fvar.vname + "}",
                shaded=True,
                color="orange",
                recordformat=True)
            self._dotgraph.add_edge(
                self.nodeprefix + "init", self.nodeprefix + self.path[0])

        return self._dotgraph

    def init_is_exposed(self) -> bool:
        result = True
        for p in self.path:
            instrs = self.rdef_instructions(p)
            if any(not instr.has_control_flow() for instr in instrs):
                result = False
        return result

    def is_exposed(self, n: str) -> bool:
        index = self.pathindex(n)
        for i in range(index + 1, len(self.path)):
            node = self.path[i]
            instrs = self.rdef_instructions(node)
            if any(not instr.has_control_flow() for instr in instrs):
                return False
        return True

    def replace_text(self, txt: str) -> str:
        result = txt
        for src in sorted(self._replacements, key=lambda x: len(x), reverse=True):
            result = result.replace(src, self._replacements[src])
        return result

    def get_branch_instruction(self, n: str) -> Optional["Instruction"]:
        src = self.function.cfg.blocks[n]
        instraddr = src.lastaddr
        return self.function.instruction(instraddr)

    def rdef_instructions(self, n: str) -> List["Instruction"]:
        block = self.function.blocks[n]
        lastaddr = block.lastaddr
        baddr = int(n, 16)
        xaddr = int(lastaddr, 16)
        result: List["Instruction"] = []
        for i in self._rdefinstrs:
            if i == "init":
                continue
            ix = int(i, 16)
            if ix >= baddr and ix <= xaddr:
                instr = block.instructions[i]
                result.append(instr)
        return result

    def add_node(self, n: str) -> None:
        nodename = self.nodeprefix + n
        rdefinstrs = self.rdef_instructions(n)
        blocktxt = n
        color: Optional[str] = None
        fillcolor: Optional[str] = None
        if len(rdefinstrs) > 0:
            conditions: List[str] = []
            pinstrs: List[str] = []
            for instr in rdefinstrs:
                (hlinstrs, _) = instr.ast_prov(self.astree)
                pinstrs.extend(str(hlinstr) for hlinstr in hlinstrs)
                if instr.has_control_flow():
                    (cc, _) = instr.ast_cc_condition_prov(self.astree)
                    conditions.append(str(cc))
            if self.is_exposed(n):
                if any(instr.has_control_flow() for instr in rdefinstrs):
                    fillcolor = "yellow"
                else:
                    fillcolor = "orange"
            if len(conditions) > 0:
                blocktxt = (
                    "{" + n + "|" + ("if " + "\\n".join(conditions))
                    + "|" + "\\n".join(pinstrs) + "}")
            else:
                blocktxt = ("{" + n + "|" + "\\n".join(pinstrs) + "}")
        self._dotgraph.add_node(
            str(nodename),
            labeltxt=blocktxt,
            shaded=True,
            color=color,
            fillcolor=fillcolor,
            recordformat=True)

    def add_edge(self, n1: str, n2: str) -> None:
        nodename1 = self.nodeprefix + n1
        nodename2 = self.nodeprefix + n2
        srcblock = self.function.block(n1)
        labeltxt: Optional[str] = None
        if len(self.function.cfg.edges[n1]) == 2:
            tgtedges = self.function.cfg.edges[n1]
            branchinstr = self.get_branch_instruction(n1)
            if branchinstr and branchinstr.is_branch_instruction:
                ftconds = branchinstr.ft_conditions
                if len(ftconds) == 2:
                    if n2 == tgtedges[0]:
                        astcond = branchinstr.ast_condition_prov(
                            self.astree, reverse=True)
                    else:
                        astcond = branchinstr.ast_condition_prov(
                            self.astree, reverse=False)
                    labeltxt = str(astcond[0])
        self._dotgraph.add_edge(nodename1, nodename2, labeltxt=labeltxt)
