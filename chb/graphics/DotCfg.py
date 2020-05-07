# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

from chb.util.DotGraph import DotGraph

class DotCfg(object):

    def __init__(self,graphname,fn,
                     looplevelcolors=[],     # [ color numbers ]
                     showpredicates=False,   # show branch predicates on edges
                     showcalls=False,        # show call instrs on nodes
                     mips=False,     # for mips subtract 4 from block end addr
                     sink=None,      # restrict paths to basic block destination
                     segments=[]):   # restrict paths to include these basic blocks
        self.fn = fn
        self.graphname = graphname
        self.looplevelcolors = looplevelcolors
        self.showpredicates = showpredicates
        self.showcalls = showcalls
        self.mips = mips
        self.sink = sink
        self.segments = segments
        self.pathnodes = set([])
        self.dotgraph = DotGraph(graphname)

    def build(self):
        if not self.sink is None:
            self.restrict_nodes(self.sink)
        elif len(self.segments) > 0:
            self.restrict_paths(self.segments)
        else:
            self.pathnodes = self.fn.cfg.blocks
        for n in self.fn.cfg.blocks:
            self.add_cfg_node(n)
        for e in self.fn.cfg.edges:
            self.add_cfg_edge(e)
        return self.dotgraph

    def restrict_nodes(self,sink):
        nodes = self.fn.cfg.blocks
        edges = self.fn.cfg.edges   # adjacency list n -> [ n ]
        if not sink in nodes:
            print('Sink ' + sink + ' not found in nodes')
            self.pathnodes = nodes
            return
        g = UG.DirectedGraph(nodes,edges)
        g.find_paths(self.fn.faddr,sink)
        for p in g.paths:
            print('Path: ' +  str(p))
            self.pathnodes = self.pathnodes.union(p)
        if len(self.pathnodes) == 0:
            self.pathnodes = nodes

    def restrict_paths(self,segments):
        nodes = self.fn.cfg.blocks
        edges = self.fn.cfg.edges
        for b in segments:
            if not b in nodes:
                print('Segment ' + b + ' not found in nodes')
                self.pathnodes = nodes
                return
        segments = [ self.fn.faddr ] + segments
        g  = UG.DirectedGraph(nodes,edges)
        for i in range(len(segments) - 1):
            src = segments[i]
            dst = segments[i+1]
            g.find_paths(src,dst)
        for p in g.paths:
            print('Path: ' + str(p))
            self.pathnodes = self.pathnodes.union(p)
        if len(self.pathnodes) == 0:
            self.pathnodes = nodes

    def get_branch_instruction(self,edge):
        srcblock = self.fn.cfg.blocks[edge]
        instraddr = srcblock.lastaddr
        if instraddr.startswith('B'):
            ctxtaddr = instraddr[2:].split('_')
            iaddr = int(ctxtaddr[1],16)
            if self.mips: iaddr -= 4  # delay slot
            instraddr = 'B:' + ctxtaddr[0] + '_' + hex(iaddr)
        else:
            instraddr = int(instraddr,16)
            if self.mips: instraddr -= 4  #  take into account delay slot
            instraddr = hex(instraddr)
        return self.fn.get_instruction(instraddr)

    def to_json(self):
        d  = {}
        d['nodes'] = []
        d['edges'] = {}
        for n in self.fn.cfg.blocks:
            d['nodes'].append(str(n))
        for e in self.fn.cfg.edges:
            d['edges'][str(e)] = {}
            def default():
                for tgt in self.fn.cfg.edges[e]:
                    d['edges'][str(e)][str(tgt)] = 'none'
            if len(self.fn.cfg.edges[e]) > 1:
                branchinstr = self.get_branch_instruction(e)
                if branchinstr.is_branch_instruction():
                    ftconditions = branchinstr.get_ft_conditions()
                    if len(ftconditions) > 1:
                        for i,tgt in enumerate(self.fn.cfg.edges[e]):
                            d['edges'][str(e)][str(tgt)] = ftconditions[i]
                    else:
                        default()
                else:
                    default()
            else:
                default()
        return d

    def add_cfg_node(self,n):
        if not n in self.pathnodes:
            return
        basicblock = self.fn.get_block(str(n))
        blocktxt = str(n)
        color = 'lightblue'
        if self.showcalls:
            callinstrs = basicblock.get_call_instructions()
            callinstrs = [ str(i.get_annotation()) for i in callinstrs ]
            print(' \n'.join( [ str(a) for a in callinstrs ]))
            if len(callinstrs) > 0:
                blocktxt = (blocktxt
                                + '\\n'
                                + '\\n'.join([str(a) for a in callinstrs]))
        if len(self.looplevelcolors) > 0:
            looplevels = self.fn.cfg.get_loop_levels(n)
            if len(looplevels) > 0:
                level = len(looplevels)
                if level > len(self.looplevelcolors):
                    color = self.looplevelcolors[-1]
                else:
                    color = self.looplevelcolors[level-1]
        if n == self.fn.faddr:
            color = 'purple'
        self.dotgraph.add_node(str(n),labeltxt=str(blocktxt),color=color)

    def add_cfg_edge(self,e):
        if not e in self.pathnodes:
            return
        def default():
            for tgt in self.fn.cfg.edges[e]:
                if tgt in self.pathnodes:
                    self.dotgraph.add_edge(str(e),str(tgt),labeltxt=None)
        labeltxt = None
        if len(self.fn.cfg.edges[e]) > 1:
            branchinstr = self.get_branch_instruction(e)
            if branchinstr.is_branch_instruction():
                if self.showpredicates:
                    ftconditions = branchinstr.get_ft_conditions()
                    if len(ftconditions) == 2:
                        for i,tgt in enumerate(self.fn.cfg.edges[e]):
                            if tgt in self.pathnodes:
                                labeltxt = str(ftconditions[i])
                                self.dotgraph.add_edge(str(e),str(tgt),labeltxt=labeltxt)
                    else:
                        default()
                else:
                    default()
            else:
                default()
        else:
            default()
        
            
            
                        
            
            
            
