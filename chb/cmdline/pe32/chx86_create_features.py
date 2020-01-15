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
"""Extracts features from the executable and saves them in a json file.

Feature sets extracted include: branch predicates, dll calls, unresolved
calls, and iocs (indicators of compromise). Format: feature set ->
feature -> feature count.
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

def get_ioc_name(ioc,rolename):
    if rolename.startswith('infox'):
        return rolename

if __name__ == '__main__':

    args = parse()

    try:
        (path,filename) = UF.get_path_filename('x86-pe',args.filename)
        UF.check_analysis_results(path,filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename)

    dllcalls = app.get_dll_calls()
    branchpredicates = app.get_branch_predicates()
    unresolvedcalls = app.get_unresolved_calls()
    try:
        (iocarguments,_) = app.get_ioc_arguments()   # ioc -> role-name -> (faddr,iaddr,arg)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    callcounts = {}  #  dll:name -> count

    for faddr in dllcalls:
        for instr in dllcalls[faddr]:
            tgt = instr.get_call_target().get_stub()
            dll = tgt.get_dll().lower()
            fname = tgt.get_name()
            name = dll + ':' + fname
            callcounts.setdefault(name,0)
            callcounts[name] += 1

    predicates = {}  # predicate -> count

    for faddr in branchpredicates:
        for instr in branchpredicates[faddr]:
            predicate = str(instr.get_branch_predicate())
            if '?' in predicate: continue
            if 'val@' in predicate: continue
            predicates.setdefault(predicate,0)
            predicates[predicate] += 1

    unrcallcounts = {}   # expression -> count

    for faddr in unresolvedcalls:
        for instr in unresolvedcalls[faddr]:
            tgt = str(instr.get_unresolved_call_target())
            unrcallcounts.setdefault(tgt,0)
            unrcallcounts[tgt] += 1

    iocresults = {}  # iocname -> iocvalue -> count

    for ioc in iocarguments:
        for rolename in iocarguments[ioc]:
            iocname = get_ioc_name(ioc,rolename)
            if iocname is None: continue
            if iocname.startswith('infox'):
                iocresults.setdefault('infox',{})
                infoxitem = iocname[6:]
                iocresults['infox'].setdefault(infoxitem,0)
                iocresults['infox'][infoxitem] += 1
            else:
                for (_,_,arg) in iocarguments[ioc][rolename]:
                    if not arg.is_const(): continue
                    iocresults.setdefault(iocname,{})
                    iocvalue = str(arg)
                    iocresults[iocname].setdefault(iocvalue,0)
                    iocresults[iocname][iocvalue] += 1

    result = {}

    result['predicates'] = predicates
    result['dllcalls'] = callcounts
    result['unresolvedcalls'] = unrcallcounts
    result['iocs'] = iocresults

    filename = UF.get_features_filename(path,filename)
    with open(filename,'w') as fp:
        json.dump(result,fp,indent=2)
