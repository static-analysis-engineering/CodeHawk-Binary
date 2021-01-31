#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
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
"""Script to collect summary analysis facts and store them in json format."""

import argparse
import json
import os

import chb.app.AppAccess as AP
import chb.util.fileutil as UF

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable')
    args = parser.parse_args()
    return args

def get_function_name(app,faddr):
    if app.has_function_name(faddr):
        return app.get_function_name(faddr) + ' (' + faddr + ')'
    else:
        return faddr

if __name__ == '__main__':

    args = parse()

    try:
        (path,filename) = UF.get_path_filename('mips-elf',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename,mips=True)
    callinstrs = app.get_app_calls()
    jumpconditions = app.get_jump_conditions()
    faddrs = app.get_function_addresses()
    

    result = {}
    rfunctions = result['functions'] = {}
    for faddr in faddrs:
        rfunction = rfunctions[faddr] = {}
        if app.has_function_name(faddr):
            rfunction['name'] = app.get_function_name(faddr)
        if faddr in callinstrs:
            rcalls = rfunction['calls'] = {}
            for i in callinstrs[faddr]:
                rcalls[i.iaddr] = i.get_call_facts()
        if faddr in jumpconditions:
            rjumps = rfunction['jumps'] = jumpconditions[faddr]


    filename = os.path.join(path,filename + '_facts.json')
    with open(filename,'w') as fp:
        json.dump(result,fp,indent=2,sort_keys=True)

