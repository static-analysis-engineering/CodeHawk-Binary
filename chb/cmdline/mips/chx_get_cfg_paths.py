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
"""Script to extract paths from a function control flow graph."""

import argparse

import chb.util.fileutil as UF
import chb.util.graphutil as UG
import chb.util.dotutil as UD
import chb.util.DotGraph as DG
import chb.app.AppAccess as AP


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable')
    parser.add_argument('function',help='address or name of function')
    parser.add_argument('--calltarget',help='address or name of call target')
    parser.add_argument('--block',help='address of target block')
    parser.add_argument('--conditions',help='show branch conditions on graph',
                            action='store_true')
    parser.add_argument('--graph',help='produce a graphical representation using dot',
                            action='store_true')
    parser.add_argument('--stringconstraints',help='output string constraints',
                            action='store_true')
    parser.add_argument('--calls',help='output calls along the paths',
                        action='store_true')
    parser.add_argument('--verbose',help='output all info',action='store_true')
    parser.add_argument('--maxtime',help='maximum search time',type=float)
    args  = parser.parse_args()
    return args

def terminate(msg):
    print('*' * 80)
    print(msg)
    print('*' * 80)
    exit(1)

def get_string_constraints(paths):
    sharedkonstraints = {}
    allkonstraints = {}
    for sink in paths:
        if not paths[sink]: continue
        pathconstraints = [ str(c) for c in paths[sink][0].get_constraints() if c ]
        sharedkonstraints[sink] = set(pathconstraints[:])
        allkonstraints[sink] = set([])
        for path in paths[sink]:
            pathconstraints = set([ str(c) for c in path.get_constraints() if c ])
            sharedkonstraints[sink] &= pathconstraints
            allkonstraints[sink] |= pathconstraints
    return (sharedkonstraints,allkonstraints)

def get_calls(paths):
    sharedcalls = {}
    allcalls = {}
    for sink in paths:
        if not paths[sink]: continue
        calls = paths[sink][0].get_block_call_instruction_strings()
        sharedcalls[sink] = set(calls[:])
        allcalls[sink] = set(calls[:])
        for path in paths[sink]:
            calls = set(path.get_block_call_instruction_strings())
            sharedcalls[sink] &= calls
            allcalls[sink] |= calls
    return (sharedcalls,allcalls)


if __name__ == '__main__':

    args = parse()
    try:
        (path,filename) = UF.get_path_filename('mips-elf',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if args.calltarget is None and args.block is None:
        terminate('Please add either a call target or a block address as destination.')

    if args.calltarget is not None and args.block is not None:
        terminate('Please give either a call target or a block address, not both.')

    app = AP.AppAccess(path,filename,mips=True)

    if app.is_unique_app_function_name(args.function):
        faddr = app.get_app_function_address(args.function)
    else:
        faddr = args.function

    if not app.has_function(faddr):
        terminate('No function found with address ' + args.function)

    f = app.get_function(faddr)

    if args.calltarget:
        if app.is_unique_app_function_name(args.calltarget):
            calltarget = app.get_app_function_address(args.calltarget)
        else:
            calltarget = args.calltarget
        
        instrs = f.get_call_instructions_to_target(calltarget)
        if len(instrs) == 0:
            terminate('No calls found to call target: ' + args.calltarget)

        blocksinks = { i.mipsblock.baddr:i for i in instrs }

    elif args.block:

        blocksinks = { args.block:f.get_instruction(args.block) }

    cfgpaths = {}    # blocksink -> list of paths
    cfgconstraints = {}  # blocksink -> [ baddr -> condition ]
    infeasiblepaths = []   # list of paths
    
    for sink in blocksinks:
        cfgpaths[sink] = f.cfg.get_paths(sink,maxtime=args.maxtime)     # [ MIPSCfgPath ]

    feasiblepaths = {}
    infeasiblepaths = 0
    for sink in cfgpaths:
        feasiblepaths[sink] = []
        for p in cfgpaths[sink]:
            if p.is_feasible():
                feasiblepaths[sink].append(p)
            else:
                infeasiblepaths += 1

    feasiblepathcount = sum([ len(feasiblepaths[b]) for b in feasiblepaths ])
    pathcount = feasiblepathcount + infeasiblepaths

    if args.verbose:
        print('Feasible paths:   ' + str(feasiblepathcount).rjust(4))
        print('Infeasible paths: ' + str(infeasiblepaths).rjust(4))
        print('                  ' + ('-' * 4))
        print('Total:            ' + str(pathcount).rjust(4))
        print('\n\n')

    if args.stringconstraints:
        (sharedkonstraints,allkonstraints) = get_string_constraints(feasiblepaths)
        print('\nShared constraints')
        for sink in sharedkonstraints:
            print('Sink: ' + str(sink))
            for k in sharedkonstraints[sink]:
                print('  ' + k)

    if args.calls:
        (sharedcalls,allcalls) = get_calls(feasiblepaths)
        print('\nShared calls')
        for sink in sharedcalls:
            print('Sink: ' + str(sink))
            for c in sorted(sharedcalls[sink]):
                print('  ' + c[0] + ':' + c[1] + '  ' + c[2])


    if args.graph:
        def getcolor(n):
            loopdepth = len(f.cfg.get_loop_levels(n))
            if loopdepth == 1:
                return '#FFAAAAFF'
            elif loopdepth == 2:
                return '#FF5555FF'
            elif loopdepth > 2:
                return '#FF0000FF'
            else:
                return None
        def get_edge_label(src,dst):
            if args.conditions:
                c = f.cfg.get_condition(src,dst)
                if not c is None:
                    return str(c)
            else:
                return None
        target = args.calltarget if args.calltarget else args.block
        graphname = 'cfg_' + args.function + '_' + target
        dotgraph = DG.DotGraph(graphname)
        paths = sum(cfgpaths.values(),[])
        for p in paths:
            for i in range(len(p.path) - 1):
                dotgraph.add_node(p.path[i],color=getcolor(p.path[i]))
                dotgraph.add_node(p.path[i+1],color=getcolor(p.path[i+1]))
                dotgraph.add_edge(p.path[i],p.path[i+1],labeltxt=get_edge_label(p.path[i],p.path[i+1]))

        pdffilename = UD.print_dot(app.path,filename,dotgraph)
        print('~' * 80)
        print('Restricted cfg for ' + filename + ' has been saved in '
                  + pdffilename)
        print('~' * 80)

    
