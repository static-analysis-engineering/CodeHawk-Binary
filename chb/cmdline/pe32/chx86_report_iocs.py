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

import chb.util.fileutil as UF
import chb.app.AppAccess as AP


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable')
    parser.add_argument('--verbose','-v',action='store_true',
                            help='show locations of iocs')
    parser.add_argument('--constants','-c',action='store_true',
                            help='only show values that are constant literals')
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
    try:
        (iocresults,problems) = app.get_ioc_arguments()  #  ioc -> role-name -> (faddr,iaddr,arg)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    for ioc in sorted(iocresults):
        print(('-' * 80) + '\n' + str(ioc) + '\n' + ('-' * 80))
        for rn in sorted(iocresults[ioc]):
            print(rn)
            results = {}
            for (faddr,iaddr,arg)  in iocresults[ioc][rn]:
                if args.constants:
                    if not arg.is_const(): continue
                argval = str(arg)
                results.setdefault(argval,[])
                results[argval].append((faddr,iaddr))
            for argval in sorted(results):
                print(str(len(results[argval])).rjust(8) + '  ' + str(argval))
                if args.verbose:
                    for (faddr,iaddr) in sorted(results[argval]):
                        print((' ' * 12) + faddr + ':' + iaddr)

    if len(problems) > 0:
        print('\nProblems encountered:')
        print('-' * 80)
        for p in problems:
            print(p)
            for dll in problems[p]:
                print('  ' + dll)
                for fname in problems[p][dll]:
                    print('    ' + fname)
                    for (faddr,iaddr,_,_) in problems[p][dll][fname]:
                        print('      ' + faddr + ',' + iaddr)
