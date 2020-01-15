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
"""Prints a list of indirect calls that have not been  resolved."""

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
    unrcalls = app.get_unresolved_calls()
    globaltargets = {}
    othertargets = {}

    for f in unrcalls:
        print(f)
        for i in unrcalls[f]:
            print('   ' + str(i))
            if i.has_global_value_unresolved_call_target():
                tgt = str(i.get_unresolved_call_target())
                globaltargets.setdefault(tgt,[])
                globaltargets[tgt].append(str(f) + ':' + str(i.iaddr) + '  ' + str(i))
            else:
                tgt = str(i.get_unresolved_call_target())
                othertargets.setdefault(tgt,[])
                othertargets[tgt].append(str(f) + ':' + str(i.iaddr) + '  ' + str(i))

    print('\nGlobal targets')
    for tgt in sorted(globaltargets):
        print('\n' + tgt)
        for i in sorted(globaltargets[tgt]):
            print('  ' + i)

    print('\nOther targets')
    for tgt in sorted(othertargets):
        print(tgt)
