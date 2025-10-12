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

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.DotGraph import DotGraph

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.app.Register import Register
    from chb.astinterface.ASTInterface import ASTInterface
    from chb.invariants import XXpr


class DotRdefPathNode:

    def __init__(
            self,
            astree: "ASTInterface",
            nodename: str,
            nodeprefix: str,
            exposed: bool,
            register: Optional["Register"],
            rdefinstrs: List["Instruction"],
            useinstrs: List["Instruction"],
            branchcondition: Optional[str],
            revbranchcondition: Optional[str],
    ) -> None:
        self._astree = astree
        self._nodename = nodename
        self._nodeprefix = nodeprefix
        self._exposed = exposed
        self._register = register
        self._rdefinstrs = rdefinstrs
        self._useinstrs = useinstrs
        self._branchcondition = branchcondition
        self._revbranchcondition = revbranchcondition

    @property
    def astree(self) -> "ASTInterface":
        return self._astree

    @property
    def nodename(self) -> str:
        return self._nodename

    @property
    def nodeprefix(self) -> str:
        return self._nodeprefix

    @property
    def exposed(self) -> bool:
        return self._exposed

    @property
    def register(self) -> Optional["Register"]:
        return self._register

    @property
    def rdefinstrs(self) -> Dict[str, "Instruction"]:
        return {rdef.iaddr:rdef for rdef in self._rdefinstrs}

    @property
    def useinstrs(self) -> Dict[str, "Instruction"]:
        return {use.iaddr:use for use in self._useinstrs}

    @property
    def branchcondition(self) -> Optional[str]:
        return self._branchcondition

    @property
    def revbranchcondition(self) -> Optional[str]:
        return self._revbranchcondition

    @property
    def fillcolor(self) -> Optional[str]:
        if len(self.useinstrs) > 0:
            return "lightblue"
        elif len(self.rdefinstrs) > 0 and self.exposed:
            if any(instr.has_control_flow() for instr in self.rdefinstrs.values()):
                return "yellow"
            else:
                return "orange"
        else:
            return None

    def has_active_cc_condition(self) -> bool:
        for instr in self.rdefinstrs.values():
            if instr.has_control_flow():
                if self.branchcondition:
                    (cc, _) = instr.ast_cc_condition_prov(self.astree)
                    if str(cc) == str(self.branchcondition):
                        return True
        return False

    def has_inactive_cc_condition(self) -> bool:
        for instr in self.rdefinstrs.values():
            if instr.has_control_flow():
                if self.revbranchcondition:
                    (cc, _) = instr.ast_cc_condition_prov(self.astree)
                    if str(cc) == str(self.revbranchcondition):
                        return True
        return False

    @property
    def blocktxt(self) -> str:
        if self.nodename == "init":
            default_init = "{ init | par: " + str(self.register) + ": ? }"
            fsig = self.astree.appsignature
            if self.register is not None and fsig is not None:
                optindex = fsig.index_of_register_parameter_location(self.register)
                if optindex is not None:
                    (fvar, _) = self.astree.get_formal_locindices(optindex - 1)
                    bctype = fvar.bctyp
                    return (
                        "{ init | par: "
                        + str(self.register)
                        + ": "
                        + str(bctype)
                        + " "
                        + fvar.vname
                        + "}")
                else:
                    return default_init
            else:
                return default_init

        rpinstrs: List[str] = []
        for (iaddr, instr) in self.rdefinstrs.items():
            (hlinstrs, _) = instr.ast_prov(self.astree)
            rpinstrs.extend(
                ("def: " + iaddr + ": " + str(hlinstr)) for hlinstr in hlinstrs)
        upinstrs: List[str] = []
        for (iaddr, instr) in self.useinstrs.items():
            if instr.is_return_instruction:
                rv = instr.return_value()
                if rv is not None:
                    astexpr = XU.xxpr_to_ast_def_expr(
                        rv, instr.xdata, iaddr, self.astree)
                    upinstrs.append(
                        "use: " + iaddr + ": return " + str(astexpr))
            else:
                (hlinstrs, llinstrs) = instr.ast_prov(self.astree)
                if len(hlinstrs) > 0:
                    upinstrs.extend(
                        ("use: " + iaddr + ":" + str(hlinstr)) for hlinstr in hlinstrs)
                else:
                    if len(llinstrs) == 1 and str(llinstrs[0]) == "NOP:BX":
                        upinstrs.append("use: " + iaddr + ": return R0")
                    elif len(llinstrs) > 0:
                        upinstrs.extend(
                            ("use:" + iaddr + ":" + str(llinstrs)) for llinstr in llinstrs)
                    else:
                        upinstrs.append("use: " + iaddr + ": " + str(instr.mnemonic))

        conditions: List[str] = []
        for (iaddr, instr) in self.rdefinstrs.items():
            if instr.has_control_flow():
                (cc, _) = instr.ast_cc_condition_prov(self.astree)
                if self.branchcondition:
                    if str(cc) == str(self.branchcondition):
                        status = " (active)"
                    elif str(cc) == str(self.revbranchcondition):
                        status = " (inactive)"
                    else:
                        status = ""
                else:
                    status = ""
                conditions.append("cc-cond: " + iaddr + ": " + str(cc) + status)

        if len(conditions) > 0:
            return (
                "{" + self.nodename + "|" + ("if " + "\\n".join(conditions))
                + "|" + "\\n".join(rpinstrs)
                + ("|" + "\\n".join(upinstrs) if len(upinstrs) > 0 else "")
                + "}")
        else:
            return (
                "{" + self.nodename
                + ("|" + "\\n".join(rpinstrs) if len(rpinstrs) > 0 else "")
                + ("|" + "\\n".join(upinstrs) if len(upinstrs) > 0 else "")
                + "}")


class DotRdefPath:

    def __init__(
            self,
            graphname: str,
            fn: "Function",
            astree: "ASTInterface",
            path: List[str],
            register: Optional["Register"] = None,
            nodeprefix: str = "",
            replacements: Dict[str, str] = {},
            rdefinstrs: List[str] = [],
            useinstrs: List[str] = [],
            subgraph: bool = False) -> None:

        self._fn = fn
        self._graphname = graphname
        self._astree = astree
        self._path = path
        self._register = register
        self._nodeprefix = nodeprefix
        self._subgraph = subgraph
        self._replacements = replacements
        self._rdefinstrs = rdefinstrs
        self._useinstrs = useinstrs
        self._dotgraph = DotGraph(graphname, subgraph=self.subgraph)
        self._nodes: Dict[str, DotRdefPathNode] = {}

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
    def register(self) -> Optional["Register"]:
        return self._register

    @property
    def nodeprefix(self) -> str:
        return self._nodeprefix

    @property
    def subgraph(self) -> bool:
        return self._subgraph

    @property
    def nodes(self) -> Dict[str, DotRdefPathNode]:
        return self._nodes

    def pathindex(self, baddr: str) -> int:
        for (i, n) in enumerate(self.path):
            if n == baddr:
                return i
        raise UF.CHBError("Address " + baddr + " not found in path")

    def build(self) -> Optional[DotGraph]:
        # hide paths with a single block that includes both def and use
        if len(self.path) <= 1:
            return None

        # hide paths in which a downstream def hides the def shown for
        # reachability
        if not self.is_exposed(self.path[0]):
            return None

        for i, n in enumerate(self.path):
            if i == len(self.path) - 1:
                self.add_node(n, None)
            else:
                self.add_node(n, self.path[i+1])

        for i in range(len(self.path) - 1):
            self.add_edge(self.path[i], self.path[i+1])

        return self._dotgraph

    def is_potentially_spurious(self) -> bool:
        return (
            self.nodes[self.path[0]].has_inactive_cc_condition()
            or any(self.nodes[n].has_active_cc_condition() for n in self.path[1:]))

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
        if n == "init":
            return []
        block = self.function.blocks[n]
        lastaddr = block.lastaddr
        baddr = int(n, 16)
        xaddr = int(lastaddr, 16)
        result: List["Instruction"] = []
        for i in self._rdefinstrs:
            if i == "init":
                continue
            if i.endswith("_clobber"):
                i = i[:-8]
            ix = int(i, 16)
            if ix >= baddr and ix <= xaddr:
                instr = block.instructions[i]
                result.append(instr)
        return result

    def use_instructions(self, n: str) -> List["Instruction"]:
        if n == "init":
            return []
        block = self.function.blocks[n]
        lastaddr = block.lastaddr
        baddr = int(n, 16)
        xaddr = int(lastaddr, 16)
        result: List["Instruction"] = []
        for i in self._useinstrs:
            if i == "init":
                continue
            ix = int(i, 16)
            if ix >= baddr and ix <= xaddr:
                instr = block.instructions[i]
                result.append(instr)
        return result

    def add_node(self, n: str, successor: Optional[str]) -> None:
        branchconds = self.node_branch_conditions(n, successor)
        rdefnode = DotRdefPathNode(
            self.astree,
            n,
            self.nodeprefix,
            self.is_exposed(n),
            self.register,
            self.rdef_instructions(n),
            self.use_instructions(n),
            branchconds[0] if branchconds else None,
            branchconds[1] if branchconds else None)
        self._nodes[n] = rdefnode

        if n!= self.path[0] and rdefnode.has_active_cc_condition():
            fillcolor: Optional[str] = "red"
        elif n == self.path[0] and rdefnode.has_inactive_cc_condition():
            fillcolor = "red"
        else:
            fillcolor = rdefnode.fillcolor

        self._dotgraph.add_node(
            self.nodeprefix + n,
            labeltxt=rdefnode.blocktxt,
            shaded=True,
            color=None,
            fillcolor=fillcolor,
            recordformat=True)

    def node_branch_conditions(
            self, n: str, successor: Optional[str]) -> Optional[Tuple[str, str]]:
        """Return T, F condition for the exit instr of node n, dependent on successor """

        if successor is None:
            return None

        if n in self.function.cfg.edges and len(self.function.cfg.edges[n]) == 2:
            tgtedges = self.function.cfg.edges[n]
            branchinstr = self.get_branch_instruction(n)
            if branchinstr and branchinstr.is_branch_instruction:
                ftconds = branchinstr.ft_conditions
                if len(ftconds) == 2:
                    (tcond, _) = branchinstr.ast_condition_prov(
                        self.astree, reverse=True)
                    (fcond, _) = branchinstr.ast_condition_prov(
                        self.astree, reverse=False)
                    if successor == tgtedges[0]:
                        return (str(tcond), str(fcond))
                    else:
                        return (str(fcond), str(tcond))
        return None

    def add_edge(self, n1: str, n2: str) -> None:
        nodename1 = self.nodeprefix + n1
        nodename2 = self.nodeprefix + n2
        if n1 == "init":
            self._dotgraph.add_edge(nodename1, nodename2, labeltxt=None)
            return
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
