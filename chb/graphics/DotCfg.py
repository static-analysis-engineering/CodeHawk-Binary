# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

import chb.util.graphutil as UG

from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, TYPE_CHECKING

from chb.util.DotGraph import DotGraph

if TYPE_CHECKING:
    import chb.app.CfgBlock
    import chb.app.Function
    import chb.app.Instruction


class DotCfg:

    def __init__(
            self,
            graphname: str,
            fn: "chb.app.Function.Function",
            looplevelcolors: List[str] = [],     # [ color numbers ]
            showpredicates: bool = False,   # show branch predicates on edges
            showcalls: bool = False,        # show call instrs on nodes
            showinstr_opcodes: bool = False,  # show all instrs on nodes
            showinstr_text: bool = False,  # show all instr annotations on nodes
            mips: bool = False,     # for mips subtract 4 from block end addr
            sink: str = None,      # restrict paths to basic block destination
            segments: List[str] = [],  # restrict paths to include these basic blocks
            # replacement text for node and edge labels
            replacements: Dict[str, str] = {}) -> None:
        self.fn = fn
        self.graphname = graphname
        self.looplevelcolors = looplevelcolors
        self.showpredicates = showpredicates
        self.showcalls = showcalls
        self.showinstr_opcodes = showinstr_opcodes
        self.showinstr_text = showinstr_text
        self.mips = mips
        self.sink = sink
        self.segments = segments
        self.replacements = replacements
        self.pathnodes: Set[str] = set([])
        self.dotgraph = DotGraph(graphname)

    def build(self) -> DotGraph:
        if self.sink is not None:
            self.restrict_nodes(self.sink)
        elif len(self.segments) > 0:
            self.restrict_paths(self.segments)
        else:
            self.pathnodes = set(self.fn.cfg.blocks.keys())
        for n in self.fn.cfg.blocks:
            self.add_cfg_node(n)
        for e in self.fn.cfg.edges:
            self.add_cfg_edge(e)
        return self.dotgraph

    def restrict_nodes(self, sink: str) -> None:
        nodes = self.fn.cfg.blocks
        edges = self.fn.cfg.edges   # adjacency list n -> [ n ]
        if sink not in nodes:
            print('Sink ' + sink + ' not found in nodes')
            self.pathnodes = set(nodes.keys())
            return
        g = UG.DirectedGraph(list(nodes.keys()), edges)
        g.find_paths(self.fn.faddr, sink)
        for p in g.paths:
            print('Path: ' + str(p))
            self.pathnodes = self.pathnodes.union(p)
        if len(self.pathnodes) == 0:
            self.pathnodes = set(nodes.keys())

    def restrict_paths(self, segments: List[str]) -> None:
        nodes = self.fn.cfg.blocks
        edges = self.fn.cfg.edges
        for b in segments:
            if b not in list(nodes.keys()):
                print('Segment ' + b + ' not found in nodes')
                self.pathnodes = set(nodes.keys())
                return
        segments = [self.fn.faddr] + segments
        g = UG.DirectedGraph(list(nodes.keys()), edges)
        for i in range(len(segments) - 1):
            src = segments[i]
            dst = segments[i+1]
            g.find_paths(src, dst)
        for p in g.paths:
            print('Path: ' + str(p))
            self.pathnodes = self.pathnodes.union(p)
        if len(self.pathnodes) == 0:
            self.pathnodes = set(nodes.keys())

    def get_branch_instruction(
            self,
            edge: str) -> "chb.app.Instruction.Instruction":
        srcblock = self.fn.cfg.blocks[edge]
        instraddr = srcblock.lastaddr
        if instraddr.startswith('B'):
            ctxtaddr = instraddr[2:].split('_')
            iaddr_i = int(ctxtaddr[1], 16)
            if self.mips:
                iaddr_i -= 4  # delay slot
            instraddr = 'B:' + ctxtaddr[0] + '_' + hex(iaddr_i)
        else:
            instraddr_i = int(instraddr, 16)
            if self.mips:
                instraddr_i -= 4  # take into account delay slot
            instraddr = hex(instraddr_i)
        return self.fn.instruction(instraddr)

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        d['nodes'] = []
        d['edges'] = {}
        for n in self.fn.cfg.blocks:
            d['nodes'].append(str(n))

        for e in self.fn.cfg.edges:
            d['edges'][str(e)] = {}

            def default() -> None:
                for tgt in self.fn.cfg.edges[e]:
                    d['edges'][str(e)][str(tgt)] = 'none'

            if len(self.fn.cfg.edges[e]) > 1:
                branchinstr = self.get_branch_instruction(e)
                if branchinstr.is_branch_instruction:
                    ftconditions = branchinstr.ft_conditions
                    if len(ftconditions) > 1:
                        for i, tgt in enumerate(self.fn.cfg.edges[e]):
                            d['edges'][str(e)][str(tgt)] = ftconditions[i]
                    else:
                        default()
                else:
                    default()
            else:
                default()
        return d

    def replace_text(self, txt: str) -> str:
        result = txt
        for src in sorted(self.replacements, key=lambda x: len(x), reverse=True):
            result = result.replace(src, self.replacements[src])
        return result

    def add_cfg_node(self, n: str) -> None:
        if n not in self.pathnodes:
            return
        basicblock = self.fn.block(str(n))
        blocktxt = str(n)
        color = 'lightblue'
        if self.showinstr_opcodes:
            instrs = basicblock.instructions.values()
            pinstrs = [i.opcodetext for i in instrs]
            blocktxt = (
                blocktxt
                + "\\n"
                + "\\n".join(pinstrs))
        elif self.showinstr_text:
            instrs = basicblock.instructions.values()
            pinstrs = [i.annotation for i in instrs]
            blocktxt = (
                blocktxt
                + "\\n"
                + "\\n".join(pinstrs))
        elif self.showcalls:
            callinstrs = basicblock.call_instructions
            pcallinstrs = [i.annotation for i in callinstrs]
            print(' \n'.join([str(a) for a in pcallinstrs]))
            if len(callinstrs) > 0:
                blocktxt = (
                    blocktxt
                    + '\\n'
                    + '\\n'.join(pcallinstrs))
        if len(self.looplevelcolors) > 0:
            looplevels = self.fn.cfg.loop_levels(n)
            if len(looplevels) > 0:
                level = len(looplevels)
                if level > len(self.looplevelcolors):
                    color = self.looplevelcolors[-1]
                else:
                    color = self.looplevelcolors[level-1]
        # if n == self.fn.faddr:
        #    color = 'purple'
        blocktxt = self.replace_text(blocktxt)
        self.dotgraph.add_node(str(n), labeltxt=str(blocktxt), color=color)

    def add_cfg_edge(self, e: str) -> None:
        if e not in self.pathnodes:
            return

        def default() -> None:
            for tgt in self.fn.cfg.edges[e]:
                if tgt in self.pathnodes:
                    self.dotgraph.add_edge(str(e), str(tgt), labeltxt=None)

        labeltxt: Optional[str] = None
        if len(self.fn.cfg.edges[e]) > 1:
            if self.showpredicates:
                branchinstr = self.get_branch_instruction(e)
                if branchinstr and branchinstr.is_branch_instruction:
                    ftconditions = branchinstr.ft_conditions
                    if len(ftconditions) == 2:
                        for i, tgt in enumerate(self.fn.cfg.edges[e]):
                            if tgt in self.pathnodes:
                                labeltxt = str(ftconditions[i])
                                labeltxt = self.replace_text(labeltxt)
                                self.dotgraph.add_edge(
                                    str(e), str(tgt), labeltxt=labeltxt)
                    else:
                        default()
                else:
                    default()
            else:
                default()
        else:
            default()
