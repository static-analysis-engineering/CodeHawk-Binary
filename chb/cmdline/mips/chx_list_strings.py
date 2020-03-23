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
"""Script to list the strings referenced in functions.

This script lists strings that are referenced in functions to enable 
function maching between a binary and its (conjectured) source code 
(the KTAdvance C analyzer can produce a similar list for source code 
as a reference). The script prints out the strings per function and 
saves a json file in the .chu directory associated with the executable.
"""

import argparse
import json

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
        (path,filename) = UF.get_path_filename('mips-elf',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    result = {}  # gvar -> faddr -> count

    app = AP.AppAccess(path,filename,mips=True)
    functionnames = app.userdata.get_function_names()

    result = app.get_strings()  # faddr -> string list

    for faddr in sorted(result):
        if len(result[faddr]) > 0:
            print(faddr)
            for s in result[faddr]:
                print('  ' + s)

    filename = UF.get_xref_filename(path,filename,'strings')
    d = {}
    for faddr in result:
        if len(result[faddr]) > 0:
            d[faddr] = result[faddr]
    with open(filename,'w') as fp:
        json.dump(d,fp,indent=3)

