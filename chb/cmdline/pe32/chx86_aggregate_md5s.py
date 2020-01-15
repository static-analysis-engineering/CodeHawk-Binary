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
"""Script to aggregate statistics on md5 function hashes.

This script collects md5 function hashes from all executables listed in 
the index files indicated by the keys arguments.
"""

import argparse
import os
import json

import chb.util.fileutil as UF
import chb.app.AppAccess as AP

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--atfis',nargs='*',default=[],
                            help='index names of files in analysistargettable for x86-pe')
    parser.add_argument('--threshold','-t',type=float,default=0.5,
                            help='upper bound on distance metric')
    parser.add_argument('--exclude_clusters','-x',nargs='*',default=[],
                            help='exclude executables from these clusters')
    parser.add_argument('--include_clusters','-i',nargs='*',default=[],
                            help='only include executables from these clusters'),
    parser.add_argument('--show_functions','-f',type=int,default=None,
                            help='show assembly code of shared functions up to length')
    parser.add_argument('--save',help='save clusters to named file')
    args = parser.parse_args()
    return args

def match(p,q):
    count = 0
    for h in p:
        if h in q: count += 1
    return count

def distance(p,q):
    lenp = len(p)
    lenq = len(q)
    minlen = min(lenp,lenq)
    matches = match(p,q)
    if minlen > 0:
        return 1.0 - (float(matches) / float(minlen))
    else:
        return 1.0

profiles = {}           # atfi:atxi -> 'md5s'
                        #   -> hash -> function(s) -> { instrs, names }
clusters = {}

hashinfos = {}          # hash -> { instrs, names }

listedclusters = {}     # atfi:atxi -> [ cluster names ]

missingmd5s = []

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

def set_profiles(atfi,records,includes,excludes):
    for atxi in records:
        r = records[atxi]
        if satisfies_spec(r,includes,excludes):
            name = UF.mk_atsc(atfi,atxi)
            if 'clusters' in r and len(r['clusters']) > 0:
                listedclusters[name] = r['clusters']
            if is_representative(r):
                try:
                    (path,filename,_) = UF.get_path_filename_deps('x86-pe',name)
                except:
                    print('**** problem with ' + name)
                    continue
                md5filename = UF.get_md5profile_filename(path,filename)
                if os.path.isfile(md5filename):
                    with open(md5filename,'r') as fp:
                        profiles.setdefault(name,{})
                        profiles[name]['md5s'] = json.load(fp)['md5s']
                else:
                    missingmd5s.append(name)
                    print('Missing: ' + name)
            else:
                rep = get_representative(atfi,r)
                profiles.setdefault(rep,{})
                profiles[rep].setdefault('md5s',[])
                profiles[rep].setdefault('duplicates',[])
                profiles[rep]['duplicates'].append(name)

def record_hashinfo(hash,frec):
    if not h in hashinfos: hashinfos[h] = {}
    if not 'instrs' in hashinfos[h]: hashinfos[h]['instrs'] = []
    instrs = frec['instrs']
    if not instrs in hashinfos[h]['instrs']:
        hashinfos[h]['instrs'].append(instrs)
    if 'names' in frec:
        if not 'names' in hashinfos[h]:
            hashinfos[h]['names'] = []
        for n in frec['names']:
            if not n in hashinfos[h]['names']:
                hashinfos[h]['names'].append(n)

def show_function(show,fnspec,instrs):
    if show is None or show < instrs:
        return ('-' * 80)
    else:
        lines = []
        (s,fa) = fnspec
        try:
            (path,filename) = UF.get_path_filename('x86-pe',s)
        except UF.CHBError as e:
            return str(e.wrap())
        app = AP.AppAccess(path,filename)
        if app.has_function(fa):
            f = app.get_function(fa)
            lines.append('-' * 80)            
            if f is None:
                lines.append('Unable to find function ' + fa)
                lines.append('-' * 80)
            else:
                try:
                    lines.append(f.to_string(esp=True,opcodetxt=True))
                except:
                    print('Unable to print function ' + fa + ' for ' + s
                              + ' (format issues probably)')
        else:
            lines.append('-' * 80)
            lines.append('Function ' + fa + ' not found')
            lines.append('-' * 80)
        return '\n'.join(lines)

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
        executables = UF.get_atfi_executables('x86-pe',atfi)
        set_profiles(atfi,executables,includes,excludes)

    result = {}

    for k in profiles:
        if not 'md5s' in profiles[k]:
            print('Key error for md5s in  ' + k + ': original missing for duplicates')
            continue
            # exit(1)
        profile = profiles[k]['md5s']
        for h in profile:
            if not h in result: result[h] = []
            for fa in profile[h]:
                result[h].append((k,fa))
                record_hashinfo(h,profile[h][fa])

    resultlengths = {}
    for h in result:
        rlen = len(result[h])
        if not rlen in resultlengths: resultlengths[rlen] = {}
        resultlengths[rlen][h] = result[h]

    for rlen in sorted(resultlengths):
        if rlen == 1:
            print(str(len(resultlengths[rlen])) + ' unique functions')
            print('-' * 80)
            continue
        print('\n' + str(rlen) + ' instances (' + str(len(resultlengths[rlen])) + ')' )
        print('-' * 80)
        for h in sorted(resultlengths[rlen]):
            names = '[' + ','.join(hashinfos[h]['names']) + ']' if 'names' in hashinfos[h] else ''
            print('\n' + h + ' (' + str(hashinfos[h]['instrs']) + ' instrs) ' + names)            
            print(show_function(args.show_functions,
                                    resultlengths[rlen][h][0],hashinfos[h]['instrs'][0]))
            for (p,fa) in sorted(resultlengths[rlen][h],key=lambda(r):r[0]):
                print('   ' + p.ljust(10) + '  ' + fa)

    for k in profiles:
        if 'md5s' in profiles[k]: continue
        print('No md5s for ' + k)
        print('\nMissing md5: ')
        for x in missingmd5s:
            print(x)

    sumf = sum( [ len(profiles[k]['md5s']) for k in profiles if 'md5s' in profiles[k] ] )

    sumd = len(result)
    print('=' * 80)
    print('Functions: ' + str(sumf) + ' (distinct: ' + str(sumd) + ')' )
    print('=' * 80)

    for k in sorted(profiles,key=lambda(k):len(profiles[k]['md5s']),reverse=True):
        pp = profiles[k]['md5s']
        lenp = len(profiles[k]['md5s'])
        assigned = False
        for q in clusters:
            pq = profiles[q]['md5s']
            dpq = distance(pp,pq)
            if dpq < args.threshold:
                clusters[q].append(k)
                assigned = True
                break
        if not assigned:
            clusters[k] = []
            clusters[k].append(k)

    for k in sorted(clusters,key=lambda(c):(len(clusters[c]),c)):
        clusternames = listedclusters.get(k,[])
        pclusternames = ','.join([c for c in clusternames ])
        print('   Cluster ' + str(k) + ' (' + str(len(clusters[k])) + ') ' + pclusternames)
        pp = profiles[k]['md5s']
        for q in sorted(clusters[k]):
            if 'duplicates' in profiles[q]:
                prdup = ' (+ ' + str(len(profiles[q]['duplicates'])) + ' duplicates)'
            else:
                prdup = ''
            if len(clusters[k]) == 1:
                print('       ' + q + prdup)
            else:
                pq = profiles[q]['md5s']
                qclusters = listedclusters.get(q,[])
                if len(qclusters) > 0:
                    pqclusters = ' (' +  ' ,'.join(qclusters) + ')'
                else:
                    pqclusters = ''
                print('        ' + q + prdup + ' (' + str(distance(pp,pq)) + ')' + pqclusters)
    print('Clusters: ' + str(len(clusters)) + ' for ' + str(len(profiles)) +
          ' executables')

    if not args.save is None:

        result = {}
        for k in clusters:
            result[k] = {}
            pp = profiles[k]['md5s']
            if len(clusters[k]) == 1:
                result[k][k] = [ 0.0, len(pp) ]
            else:
                for q in clusters[k]:
                    pq = profiles[q]['md5s']
                    result[k][q] = [ distance(pp,pq), len(pq) ]
        with open(args.save + '.json','w') as fp:
            json.dump(result,fp,sort_keys=True,indent=2)

    print('\nMissing md5: ')
    for x in sorted(missingmd5s):
        print(x)
