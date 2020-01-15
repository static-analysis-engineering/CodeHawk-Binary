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
"""This script extracts features per function and saves them in a json file.

Features extracted include: branch predicates, unresolved calls, structured
expressions, return expression, dll calls, string arguments, ioc arguments,
md5 function hash.
"""

import argparse
import json
import os

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

    metrics = app.get_result_metrics()
    dllcalls = app.get_dll_calls()
    appcalls = app.get_app_calls()
    branchpredicates = app.get_branch_predicates()
    unresolvedcalls = app.get_unresolved_calls()
    structuredlhsvars = app.get_structured_lhs_variables()
    structuredrhsxprs = app.get_structured_rhs_expressions()
    retxprs = app.get_return_expressions()
    stringxrefs = app.stringxrefs.get_function_xref_strings()
    iocarguments = app.get_fn_ioc_arguments()   # faddr -> [ (rolename,paramname,argvalue) ]
    md5profile = app.get_md5_profile()['md5s']  # md5 -> faddr -> instruction count

    fnmd5s = {}   #  faddr -> md5
    for md5 in md5profile:
        for faddr in md5profile[md5]:
            fnmd5s[faddr] = md5

    result = {}

    for faddr in fnmd5s:
        result.setdefault(faddr,{})
        result[faddr]['md5'] = fnmd5s[faddr]
        result[faddr]['featuresets'] = {}

    def strf(fn):
        faddr = fn.faddr
        result.setdefault(faddr,{})
        result[faddr].setdefault('featuresets',{})
        fresult = result[faddr]['featuresets']['structure'] = {}
        if faddr in fnmd5s:
            fresult['md5'] = fnmd5s[faddr]
        fresult['blocks'] = fn.get_blocks()
        fresult['instrs'] = fn.get_instrs()
        fresult['loops'] = fn.get_loop_count()
        fresult['loopdepth'] = fn.get_loop_depth()
    metrics.iter(strf)

    for faddr in structuredlhsvars:
        fresult = result[faddr]['featuresets']['structuredlhs'] = {}
        for lhs in structuredlhsvars[faddr]:
            lhs =  str(lhs)
            fresult.setdefault(lhs,0)
            fresult[lhs] += 1

    for faddr in stringxrefs:
        result[faddr]['featuresets']['strings'] = stringxrefs[faddr]

    for faddr in structuredrhsxprs:
        fresult = result[faddr]['featuresets']['structuredrhs'] = {}
        for rhs in structuredrhsxprs[faddr]:
            rhs = str(rhs)
            fresult.setdefault(rhs,0)
            fresult[rhs] += 1

    for faddr in retxprs:
        if len(retxprs[faddr]) == 1 and str(retxprs[faddr][0]) == 'eax': continue
        fresult = result[faddr]['featuresets']['returnexprs'] = {}
        for rx in retxprs[faddr]:
            rx = str(rx)
            if rx == 'eax': continue
            fresult.setdefault(rx,0)
            fresult[rx] += 1

    for faddr in appcalls:
        fresult = result[faddr]['featuresets']['appcalls'] = {}
        for instr in appcalls[faddr]:
            tgt = str(instr.get_call_target().get_address())
            fresult.setdefault(tgt,0)
            fresult[tgt] += 1

    for faddr in dllcalls:
        result[faddr]['featuresets']['dllcalls'] = {}
        fresult = result[faddr]['featuresets']['dllcalls']
        for instr in dllcalls[faddr]:
            tgt = instr.get_call_target().get_stub()
            dll = tgt.get_dll().lower()
            fname = tgt.get_name()
            name = dll + ':' + fname
            fresult.setdefault(name,0)
            fresult[name] += 1

    for faddr in iocarguments:
        fiocresult = result[faddr]['featuresets']['iocargs'] = {}
        fdllresult = result[faddr]['featuresets']['dllargs'] = {}
        for (rolename,paramname,argval) in iocarguments[faddr]:
            rolefeature = rolename + ':' + str(argval)
            namefeature = paramname + ':' + str(argval)
            fiocresult.setdefault(rolefeature,0)
            fdllresult.setdefault(namefeature,0)
            fiocresult[rolefeature] += 1
            fdllresult[namefeature] += 1

    for faddr in branchpredicates:
        result[faddr]['featuresets']['predicates'] = {}
        fresult = result[faddr]['featuresets']['predicates']
        for instr in branchpredicates[faddr]:
            predicate = str(instr.get_branch_predicate())
            if '?' in predicate: continue
            if '@val' in predicate: continue
            fresult.setdefault(predicate,0)
            fresult[predicate] += 1

    for faddr in unresolvedcalls:
        fresult = result[faddr]['featuresets']['unresolvedcalls'] = {}
        for instr in unresolvedcalls[faddr]:
            tgt = str(instr.get_unresolved_call_target())
            fresult.setdefault(tgt,0)
            fresult[tgt] += 1

    featurecount = 0
    distinct = 0

    for faddr in result:
        for fs in result[faddr]['featuresets']:
            if fs == 'structure': continue
            featurecount += sum (result[faddr]['featuresets'][fs].values())
            distinct += len(result[faddr]['featuresets'][fs])

    print('Created ' + str(featurecount) + ' features (' + str(distinct) + ' distinct)')

    filename = UF.get_fn_features_filename(path,filename)
    with open(filename,'w') as fp:
        json.dump(result,fp,indent=2,sort_keys=True)
