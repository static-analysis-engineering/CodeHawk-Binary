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
"""Prints an annotated assembly listing of one or more or all functions."""

import argparse

import chb.util.fileutil as UF
import chb.app.AppAccess as AP

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable to be analyzed')
    parser.add_argument('--functions',nargs='*',help='list of function addresses',default=[])
    parser.add_argument('--assembly',help='include assembly code',action='store_true')
    parser.add_argument('--bytes',help='include bytes',action='store_true')
    parser.add_argument('--callers',help='show callers',action='store_true')
    parser.add_argument('--esp',help='show stackpointer offset',action='store_true')
    parser.add_argument('--bytestring',help='show bytes as a string', action='store_true')
    parser.add_argument('--hash',action='store_true',help='show hash of function bytes')
    parser.add_argument('--operandvalues',action='store_true',help='show operand values')
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
    functionnames = app.userdata.get_function_names()
    def has_function_name(faddr): return functionnames.has_function_name(faddr)
    def get_function_name(faddr): return functionnames.get_function_name(faddr)

    if 'all' in args.functions:
        showfunctions = sorted(app.get_function_addresses())
    else:
        showfunctions = args.functions

    for faddr in showfunctions:
        if app.has_function(faddr):
            f = app.get_function(faddr)
            if f is None:
                print('\n **** Unable to find function ' + faddr + ' *****\n\n')
                continue
            print('\nFunction ' + faddr)
            print('-' * 80)
            print(f.to_string(bytestring=args.bytestring,bytes=args.bytes,
                                  esp=args.esp,opcodetxt=args.assembly,
                                  hash=args.hash))

            if args.callers:
                print('\nCallers:')
                print('-' * 80)
                calls = app.get_calls_to_app_function(faddr)
                for tgtfaddr in sorted(calls):
                    print(tgtfaddr)
                    for callinstr in sorted(calls[tgtfaddr],key=lambda x:x.iaddr):
                        print('  ' + callinstr.iaddr + '  '
                                  + callinstr.to_string(opcodetxt=False))

            if args.operandvalues:
                print('\n\nOperand values')
                opvalues = f.get_operand_values()
                for ia in sorted(opvalues):
                    print(str(ia) + '  ' + ', '.join(str(x) for x in opvalues[ia]))

                print('\nOperands')
                operands = f.get_operands()
                for ia in sorted(operands):
                    print(str(ia) + '  ' + ', '.join(str(x)  for x in operands[ia]))
        else:
            print('Function ' + faddr + ' not found')
            print('Functions available: ')
            for faddr in app.get_function_addresses():
                print(faddr)
            

    
