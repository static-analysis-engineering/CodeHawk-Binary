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

import argparse

import chb.app.AppAccess as AP
import chb.util.fileutil as UF

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable to be analyzed')
    parser.add_argument('--aggregate',help='aggregate argument values per dll function',
                            action='store_true')
    args = parser.parse_args()
    return args

if __name__ == '__main__':

    args = parse()

    try:
        (path,filename,deps) = UF.get_path_filename_deps('x86-pe',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename,deps=deps)
    dllcalls = app.get_dll_calls()

    result = {}   # name of Dll -> name of function -> instr

    for faddr in dllcalls:
        for instr in dllcalls[faddr]:
            tgt = instr.get_call_target().get_stub()
            dll = tgt.get_dll()
            fname = tgt.get_name()
            result.setdefault(dll,{})
            result[dll].setdefault(fname,[])
            result[dll][fname].append(instr)

    summaryproblems = {}

    for dll in sorted(result):
        print('\n' + dll)
        for fname in sorted(result[dll]):
            print('\n  ' + fname)
            for instr in sorted(result[dll][fname],key=lambda i:(i.asmfunction.faddr,i.iaddr)):
                faddr = instr.asmfunction.faddr
                try:
                    print('    ' + faddr + ',' + instr.iaddr + '  '
                            + ', '.join([ n + ':' +  str(x)
                                              for (n,x) in instr.get_annotated_call_arguments()]))
                except UF.CHBError as e:
                    summaryproblems.setdefault(dll,{})
                    summaryproblems[dll].setdefault(fname,[])
                    summaryproblems[dll][fname].append(str(e))

    if args.aggregate:

        aggregates = {} # name of Dll -> name of function -> name of argument -> value -> count

        for dll in result:
            aggregates[dll] = {}
            for fname in result[dll]:
                aggregates[dll][fname] = {}
                fentry = aggregates[dll][fname]
                for instr in result[dll][fname]:
                    arguments = instr.get_annotated_call_arguments()
                    for (name,v) in arguments:
                        pv = str(v)
                        fentry.setdefault(name,{})
                        fentry[name].setdefault(pv,0)
                        fentry[name][pv] += 1

        for dll in sorted(aggregates):
            print('\n' + dll)
            for fname in sorted(aggregates[dll]):
                print('\n  ' + fname)
                for argname in sorted(aggregates[dll][fname]):
                    print('\n    ' + argname)
                    argentry = aggregates[dll][fname][argname]
                    for pv in sorted(argentry):
                        print('      ' + str(argentry[pv]).rjust(3) + '  ' + pv)

    if len(summaryproblems) > 0:
        print('\nProblems encountered with function summaries:')
        for dll in summaryproblems:
            for fname in summaryproblems[dll]:
                print('\n' + dll + ',' + fname)
                for e in summaryproblems[dll][fname]:
                    print('  ' + str(e))
