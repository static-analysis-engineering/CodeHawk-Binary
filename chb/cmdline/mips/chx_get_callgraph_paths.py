#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"""Script to extract paths from the application callgraph."""

import argparse

import chb.util.fileutil as UF
import chb.util.DotGraph as DG
import chb.util.dotutil as UD
import chb.app.Callgraph as CG
import chb.app.AppAccess as AP


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable')
    parser.add_argument('src',help='address of starting function')
    parser.add_argument('--dst',help='name or address of destination function')
    parser.add_argument('--countcfgpaths',help='count the numher of paths through cfgs',
                            action='store_true')
    parser.add_argument('--graph',help='produce a graphical representation using dot',
                            action='store_true')
    parser.add_argument('--reverse',help='reverse the call graph',action='store_true')
    args  = parser.parse_args()
    return args

if __name__ == '__main__':

    args = parse()
    try:
        (path,filename) = UF.get_path_filename('mips-elf',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename,mips=True)

    if args.src.startswith('0x'):
        if not app.has_function(args.src):
            print('*' * 80)
            print('No function found with address ' + args.src)
            print('*' * 80)
            exit(1)

    callgraph = CG.Callgraph(app)

    def getname(n):
        if n.startswith('0x') and app.has_function_name(n):
            return app.get_function_name(n) + ' (' + n + ')'
        else:
            return n

    if args.reverse:
        paths = callgraph.get_reverse_paths(args.src)
    else:
        paths = callgraph.get_paths(args.src,args.dst)
    for p in paths:
        print(', '.join(getname(n) for n in p))

    pathcounts = {}  #  (src,dst) -> number of paths through src cfg to reach dst           
    callgraphpathlengths = {}  # maximum length in basic blocks through all cfgs in path
    
    if args.countcfgpaths:
        for p in paths:
            pname = '_'.join([ str(n) for n in p ])
            callgraphpathlengths[pname] = 0
            for i in range(len(p) - 1):
                if (p[i],p[i+1]) in pathcounts: continue
                f = app.get_function(p[i])
                instrs = f.get_call_instructions_to_target(p[i+1])
                blocks = [ instr.mipsblock.baddr for instr in instrs ]
                for b in blocks:
                    bcfgpaths = f.cfg.get_paths(b)
                    callgraphpathlengths[pname] += max( [ len(bp.path) for bp in bcfgpaths ])
                    pathcounts.setdefault((p[i],p[i+1]),0)
                    pathcounts[(p[i],p[i+1])] += len(bcfgpaths)

        for e in sorted(pathcounts):
            print(str(e) + ': ' + str(pathcounts[e]))

        for p in sorted(callgraphpathlengths):
            print(str(p) + ': ' + str(callgraphpathlengths[p]))

    if args.graph:
        def getname(n):
            if n.startswith('0x') and app.has_function_name(n):
                return app.get_function_name(n)
            else:
                return n
        def getcolor(n):
            if n.startswith('0x'):
                f = app.get_function(n)
                if f.cfg.has_loops():
                    return 'red'
                else:
                    return None
            return None
        dst = '_all_' if args.dst is None else args.dst
        graphname = 'callgraph_' + args.src + '_' + dst
        dotgraph = DG.DotGraph(graphname)
        dotgraph.set_left_to_right()
        for p in paths:
            for i in range(len(p) - 1):
                dotgraph.add_node(p[i],labeltxt=getname(p[i]),color=getcolor(p[i]))
                dotgraph.add_node(p[i+1],labeltxt=getname(p[i+1]),color=getcolor(p[i+1]))
                if (p[i],p[i+1]) in pathcounts:
                    labeltxt = str(pathcounts[(p[i],p[i+1])])
                else:
                    labeltxt = None
                dotgraph.add_edge(p[i],p[i+1],labeltxt=labeltxt)

        pdffilename = UD.print_dot(app.path,filename,dotgraph)
        print('~' * 80)
        print('Restricted call graph for ' + filename + ' has been saved in '
                  + pdffilename)
        print('~' * 80)
                
        
        
                

        
