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
"""Script to match functions to reference patterns using function features."""

import argparse
import os
import json

import chb.util.fileutil as UF
import chb.app.AppAccess as AP

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--atfis','-p',nargs='*',default=[],
                            help='index names of files analysistargettable for x86-pe')
    parser.add_argument('--exclude_clusters','-x',nargs='*',default=[],
                            help='exclude executables from these clusters')
    parser.add_argument('--include_clusters','-i',nargs='*',default=[],
                            help='only include executables from these clusters'),
    parser.add_argument('--printfunctions',nargs='*',default=[])
    parser.add_argument('--patterns',type=int,
                            help='reference consists of query patterns')
    args = parser.parse_args()
    return args


def satisfies_spec(r,includes,excludes):
    if len(includes) > 0:
        if not 'clusters' in r: return False
        for c in r['clusters']:
            if any([ c.startswith(i) for i in includes]): return True
        return False
    if len(excludes) > 0:
        if not 'clusters' in r: return True
        for x in excludes:
            if any([ c.startswith(x) for c in r['clusters'] ]):
                return False
        else:
            return True
    return True

def is_representative(r):
    if 'code-rep' in r:
        return r['code-rep'][0] == r['md5']
    else:
        return True

def get_representative(atfi,r):
    if 'code-rep' in r:
        return UF.mk_atsc(atfi,r['code-rep'][1])
    else:
        print('Error in get-representative for ' + str(r['file']))
        exit(1)

fndata = {} # exe-name -> faddr -> data
fnstats = {}  # exe-name -> (fncount,fnmapped)

apps = {}  # exe-name -> app

def collect_data(atfi,records,includes,excludes,args):
    xcount = 0
    fncount = 0
    for atxi in records:
        r = records[atxi]
        if satisfies_spec(r,includes,excludes):
            name = UF.mk_atsc(atfi,atxi)
            if is_representative(r):
                try:
                    (path,filename) = UF.get_path_filename('x86-pe',name)
                    UF.check_analysis_results(path,filename)
                except UF.CHBError as e:
                    print('**** problem with ' + name + ': ' + str(e))
                    continue
                fnmapfilename = UF.get_fn_map_filename(path,filename)
                fnfeaturefilename = UF.get_fn_features_filename(path,filename)
                if not os.path.isfile(fnfeaturefilename): continue
                with open(fnfeaturefilename,'r') as fp:
                    fnfeatures = json.load(fp)
                if not os.path.isfile(fnmapfilename): continue
                xcount += 1
                fndata[name] = {}
                app = AP.AppAccess(path,filename)
                if len(args.printfunctions) > 0:
                    apps[k] = app
                metrics = app.get_result_metrics()
                fncount += metrics.get_function_count()
                with open(fnmapfilename,'r') as fp:
                    fnmap = json.load(fp)
                fnstats[name] = (metrics.get_function_count(),len(fnmap['functions']))
                for fn in fnmap['functions']:
                    if not fn in fnfeatures: continue
                    fnmd5 =  fnfeatures[fn]['md5']
                    fnrec = fndata[name][fn] = {}
                    fnmetrics = metrics.get_function_metrics(fn)
                    if fnmetrics is None:
                        print(name + ': Function ' + fn + ' not found')
                        continue
                    try:
                        fnrec['md5'] = fnmd5
                        fnrec['reffn'] = fnmap['functions'][fn]['reffn']
                        fnrec['score'] = fnmap['functions'][fn]['score']
                        fnrec['esp'] = fnmetrics.get_espp()
                        fnrec['blocks'] = fnmetrics.get_blocks()
                        fnrec['instrs'] = fnmetrics.get_instrs()
                        fnrec['unrc'] = fnmetrics.get_unresolved_calls()
                        if fnmetrics.has_name():
                            fnrec['name'] = fnmetrics.get_name()
                    except:
                        print('Problem in ' + name + ', ' + fn)
                        raise
    return(xcount,fncount)


if __name__ == '__main__':

    args = parse()

    includes = args.include_clusters
    excludes = args.exclude_clusters

    if len(includes) > 0 and len(excludes) > 0:
        print('*' * 80)
        print('Please specify either includes or excludes, but not both')
        print('*' * 80)
        exit(1)

    if 'all' in args.atfis:
        args.atfis = list(UF.get_analysis_target_executables('x86-pe').keys())

    for atfi in args.atfis:
        try:
            executables = UF.get_atfi_executables('x86-pe',atfi)
            (xcount,fncount) = collect_data(atfi,executables,includes,excludes,args)
        except UF.CHBError as e:
            print(str(e.wrap()))
            exit(1)

    print('\nStatistics')
    print('-' * 80)
    print('executable'.ljust(17) + 'function count'.rjust(20)
              + 'functions mapped'.rjust(20) + 'percent of'.rjust(23))
    if args.patterns is None:
        print('functions mapped'.rjust(80))
    else:                  
        print((str(args.patterns) + ' patterns mapped').rjust(80))
    print('-' * 80)

    pcount = args.patterns
    
    for x in sorted(fnstats,key=lambda x:float(fnstats[x][1])/float(fnstats[x][0]),reverse=True):
        (xfncount,xfnmapped) = fnstats[x]
        dn = float(pcount) if not pcount is None else float(xfncount)
        if dn > 0.0:
            fnratio = 100.0 * float(xfnmapped) / dn
            print(x.ljust(15) + '  ' + str(xfncount).rjust(20) + str(xfnmapped).rjust(20)
                      + '{0:23.1f}'.format(fnratio))

    result = {}   #  reffn -> exe-name:faddr -> data

    for x in fndata:
        for faddr in fndata[x]:
            try:
                name = x + ':' + faddr
                reffn = fndata[x][faddr]['reffn']
                result.setdefault(reffn,{})
                result[reffn][name] = fndata[x][faddr]
                result[reffn][name]['id'] = fndata[x][faddr]['md5'][:3]
            except:
                print('Problem with ' + name)
                continue

    totalfns = 0

    header = 'name'.ljust(25) + 'md5 prefix       blocks     instrs     similarity score'

    print('\nFunctions mapped')
    for reffn in sorted(result):
        ids = set( [ result[reffn][y]['id'] for y in result[reffn] ])
        distinct = len(ids)
        print('\n' + reffn + ' (' + str(len(result[reffn]))
                  + ' functions mapped, ' + str(distinct) + ' distinct)')
        print(header)
        for name in sorted(result[reffn],
                               key=lambda y:(result[reffn][y]['score'],
                                                 result[reffn][y]['id']),
                               reverse=True):
            totalfns += 1
            fndata = result[reffn][name]
            fname = ' (' + fndata['name'] + ')' if 'name' in fndata else ''
            print(name.ljust(25) + '   (' + fndata['md5'][:3] + ')    '  
                          + str(fndata['blocks']).rjust(10)
                          + str(fndata['instrs']).rjust(10)
                          + '{0:16.2f}'.format(fndata['score'])
                          + fname)

    if len(args.printfunctions) > 0:
        print('Print reference functions: ')
    print('   ' + ','.join([ str(x) for x in args.printfunctions]))
    for reffn in sorted(result):
        if reffn in args.printfunctions:
            ids = set( [ result[reffn][y]['id'] for y in result[reffn] ])            
            for name in sorted(result[reffn]):
                id = result[reffn][name]['id']
                if not id in ids: continue
                ids.discard(id)
                namecomponents = name.split(':')
                xname = namecomponents[2]
                if xname in apps:
                    app = apps[xname]
                    faddr = namecomponents[-1]
                    if app.has_function(faddr):
                        print('\n' + ('*' * 80))
                        print(xname + ':' + namecomponents[3])
                        print('*' * 80)
                        f = app.get_function(faddr)
                        print(f.to_string(bytestring=False,bytes=False,
                                    esp=True,opcodetxt=True,
                                    hash=False))
                else:
                    print(xname + ' not found in apps')
            

    print('\nEquivalence classes: ' + str(len(result)))
    print('Functions included : ' + str(totalfns))

    print('\nExecutables covered: ' + str(xcount))
    print('Functions included : ' + str(fncount))

    
