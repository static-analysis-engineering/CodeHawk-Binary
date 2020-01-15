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
"""Prints a list of application calls and their arguments if available.

Application calls are printed organized by a target application function,
followed by the arguments with which the function is invoked at the
different call sites.
"""

import argparse

import chb.app.AppAccess as AP
import chb.util.fileutil as UF

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable to be analyzed')
    args = parser.parse_args()
    return args

if __name__ == '__main__':

    args = parse()

    try:
        (path,filename) = UF.get_path_filename('x86-pe',args.filename)
        UF.check_analysis_results(path,filename)         
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename)
    appcalls = app.get_app_calls()

    result = {}   # address of function -> instr

    for faddr in sorted(appcalls):
        for instr in appcalls[faddr]:
            tgt = str(instr.get_call_target().get_address())
            result.setdefault(tgt,[])
            result[tgt].append(instr)

    for tgt in sorted(result):
        print('\n' + str(tgt))
        for instr in sorted(result[tgt]):
            faddr = instr.asmfunction.faddr
            iaddr = instr.iaddr
            print('    ' + faddr + ',' + iaddr
                      + ': ' + ', '.join(str(x) for x in instr.get_call_arguments()))
                
                
