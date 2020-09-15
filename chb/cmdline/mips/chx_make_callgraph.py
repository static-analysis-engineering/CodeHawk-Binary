#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020 Henny Sipma
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

import argparse
import json

import chb.app.AppAccess as AP
import chb.app.Callgraph as CG
import chb.util.fileutil as UF
import chb.util.dotutil as UD
import chb.graphics.DotCallgraph as DC

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable to be analyzed')
    parser.add_argument('--libcalls',nargs='*',help='show library calls',default=[])
    parser.add_argument('--sinks',nargs='*',help='restrict paths to these nodes',default=[])
    parser.add_argument('--startaddr',help='restrict paths starting from this node')
    parser.add_argument('--reverse',help='reverse the callgraph',action='store_true')
    parser.add_argument('--save',help='save the callgraph to a json file',action='store_true')
    args = parser.parse_args()
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
    callgraph = CG.Callgraph(app)

    if args.reverse:
        callgraphdata = callgraph.get_reverse_callgraph()
    else:
        callgraphdata = callgraph.edges

    if args.save:
        if args.reverse:
            jsonfilename = UF.get_xref_filename(path,filename,'callgraph_r')
        else:
            jsonfilename = UF.get_xref_filename(path,filename,'callgraph')
        with open(jsonfilename,'w') as fp:
            json.dump(callgraphdata,fp,sort_keys=True,indent=3)

    def getname(n):
        if app.has_function_name(n):
            return app.get_function_name(n)
        else:
            return n

    graphname = 'callgraph_' + filename
    dotcg = DC.DotCallgraph(graphname,callgraphdata,startaddr=args.startaddr,sinks=args.sinks,getname=getname)

    def coloring(n):
        if n.startswith('0x'):
            return 'lightblue'
        elif n in args.libcalls:
            return 'red'
        elif n.startswith('gv_'):
            return 'blue'
        elif n.startswith('call-target'):
            return 'yellow'
        else:
            return 'green'

    pdffilename = UD.print_dot(app.path,filename,dotcg.build(coloring=coloring))
    print('~' * 80)
    print('Call graph for ' + filename + ' has been saved in '
              + pdffilename)
    print('~' * 80)
