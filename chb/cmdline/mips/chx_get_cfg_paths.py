# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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
    parser.add_argument('--constraints',help='produce constraints',
                            action='store_true')
    args  = parser.parse_args()
    return args

def terminate(msg):
    print('*' * 80)
    print(msg)
    print('*' * 80)
    exit(1)

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
        terminate('No function found with address ' + args.faddr)

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
        cfgpaths[sink] = f.cfg.get_paths(sink)     # [ MIPSCfgPath ]

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

    print('Feasible paths:   ' + str(feasiblepathcount).rjust(4))
    print('Infeasible paths: ' + str(infeasiblepaths).rjust(4))
    print('                  ' + ('-' * 4))
    print('Total:            ' + str(pathcount).rjust(4))
    print('\n\n')
    
    if args.constraints:
        sharedconditions = {}
        allconditions = {}
        sharedcalls = {}
        allcalls = {}
        for sink in sorted(feasiblepaths):
            blockconditions = feasiblepaths[sink][0].get_block_condition_strings()
            blockcallinstrs = feasiblepaths[sink][0].get_block_call_instruction_strings()            
            sharedconditions[sink] = set(blockconditions[:])
            allconditions[sink] = set(blockconditions[:])
            sharedcalls[sink] = set(blockcallinstrs[:])
            allcalls[sink] = set(blockcallinstrs[:])
            for path in feasiblepaths[sink]:
                pathconditions = path.get_conditions()
                blockconditions = path.get_block_condition_strings()
                sharedconditions[sink] &= set(blockconditions[:])
                allconditions[sink] |= set(blockconditions[:])
                notcovered = []
                print('')
                print('=' * 80)
                print('Constraints to reach:')
                print('  ' + sink + ': ' + str(blocksinks[sink].get_annotation()))
                for a in blocksinks[sink].get_call_arguments():
                    if a.is_stack_address():
                        print('    ' +  str(a))
                print('=' * 80)
                pathconstraints = path.get_constraints()
                callinstrs = path.get_call_instructions()
                for i,konstraint in enumerate(pathconstraints):
                    block = path.path[i]
                    if konstraint is None:
                        if pathconditions[i] is None:
                            continue
                        else:
                            notcovered.append((i,block,str(pathconditions[i])))
                    else:
                        print('  ' + str(konstraint))
                if len(notcovered) > 0:
                    print('-' * 80)
                    print('Not yet covered: ' )
                    for (i,block,x) in sorted(notcovered):
                        print('  ' + str(i).rjust(4) + '  ' + block + ': ' + str(x))
                if len(callinstrs) > 0:
                    blockcallinstrs = path.get_block_call_instruction_strings()
                    sharedcalls[sink] &= set(blockcallinstrs[:])
                    allcalls[sink] |= set(blockcallinstrs[:])
                    print('-' * 80)
                    print('Calls: ')
                    for i,c in enumerate(callinstrs):
                        for instr in c:
                            block = path.path[i]
                            print('  ' + str(i).rjust(4) + '  ' + block + ': ' + str(instr.get_annotation()))

        print('\nShared conditions:')
        print('-' * 80)
        for sink in sharedconditions:
            print('\nSink: ' + str(sink))
            for c in sorted(sharedconditions[sink]):
                print('  ' + c[0] + ':' + c[1])

        print('\nNonshared conditions: ')
        print('-' * 80)
        for sink in allconditions:
            print('\nSink: ' + str(sink))
            for c in sorted(allconditions[sink]):
                if c in sharedconditions[sink]: continue
                print('  ' + c[0] + ':' + c[1])

        print('\nShared calls:')
        print('-' * 80)
        for sink in sharedcalls:
            print('\nSink: ' + str(sink))
            for c in sorted(sharedcalls[sink]):
                print('  ' + c[0] + ':' + c[1] + '  ' + c[2])

        print('\nNonshared calls: ')
        print('-' * 80)
        for sink in allcalls:
            print('\nSink: ' + str(sink))
            for c in sorted(allcalls[sink]):
                if c in sharedcalls[sink]: continue
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
        graphname = 'cfg_' + args.function + '_' + args.calltarget
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
            

                                                                 
            
    
