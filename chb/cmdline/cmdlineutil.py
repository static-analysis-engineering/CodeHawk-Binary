# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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

from datetime import datetime
import json
import os
import subprocess

import chb.util.fileutil as UF
import chb.cmdline.AnalysisManager as AM

def exit_with_msg(m):
    print('*' * 80)
    print(m)
    print('*' * 80)
    exit(1)

def print_info(m):
    print('~' * 80)
    print(m)
    print('~' * 80)

def print_error(m):
    print('*' * 80)
    print(m)
    print('*' * 80)

def get_md5(fname):
    md5 = subprocess.run(['md5sum',fname],stdout=subprocess.PIPE)
    return md5.stdout.decode('utf-8')[:32]

def print_architecture_failure(xinfo):
    arch = xinfo.get_architecture()
    if arch == 'x64':
        exit_with_msg('x86-64 not yet supported; hopefully soon')
    # if arch == 'arm':
    #    exit_with_msg('arm not yet supported; hopefully soon; we are currently working on it')
    exit_with_msg('File architecture not recognized')

def get_architecture(ftype):
    if 'MIPS' in ftype: return 'mips'
    if 'ARM' in ftype: return 'arm'
    if '80386' in ftype: return 'x86'
    if 'x86-64' in ftype: return 'x64'
    return '?'

def get_file_format(ftype):
    if 'ELF' in ftype: return 'elf'
    if 'PE32' in ftype: return 'pe32'
    return '?'

def print_not_supported(m):
    print('~' * 80)
    print(m)
    print('~' * 80)
    exit(0)

def print_format_failure(xinfo):
    exit_with_msg('File format not recognized')

class XInfo(object):

    def __init__(self,path,filename):
        self.timeline = {}
        self.fileinfo = {}
        self.fileinfo['path'] = path
        self.fileinfo['file'] = filename
        self.initialized = False

    def get_absolute_filename(self):
        return os.path.join(self.fileinfo['path'],self.fileinfo['file'])

    def get_xinfo_filename(self):
        return self.get_absolute_filename() + '_xinfo.json'

    def get_architecture(self): return self.fileinfo.get('arch','?')

    def is_mips(self): return self.fileinfo['arch'] == 'mips'

    def is_x86(self): return self.fileinfo['arch'] == 'x86'

    def is_arm(self): return self.fileinfo['arch'] == 'arm'

    def is_elf(self): return self.fileinfo['format'] == 'elf'

    def is_pe32(self): return self.fileinfo['format'] == 'pe32'

    def get_format(self): return self.fileinfo['format']

    def load(self):
        xinfoname = self.get_xinfo_filename()
        try:
            with open(xinfoname,'r') as fp:
                xinfo = json.load(fp)
            self.timeline = xinfo['timeline']
            self.fileinfo = xinfo['file']
            self.initialized = all(x in self.fileinfo
                                      for x in ['name','size','arch','format','md5'])
        except Exception as e:
            exit_with_msg('Error in xinfo file: ' + str(e))

    def discover(self):
        fname = self.get_absolute_filename()
        ftype = subprocess.run(['file',fname],stdout=subprocess.PIPE)
        ftype = ftype.stdout.decode('utf-8')
        self.timeline['created'] = datetime.now().isoformat(timespec='minutes')
        self.fileinfo['md5'] = get_md5(fname)
        self.fileinfo['size'] = os.path.getsize(fname)
        self.fileinfo['arch'] = get_architecture(ftype)
        self.fileinfo['format'] = get_file_format(ftype)
        if self.fileinfo['arch'] == '?':
            print_not_supported('Architecture not recognized: ' + ftype)
        if self.fileinfo['arch'] == 'x64':
            print_not_supported('Architecture x64 not yet supported; hopefully coming soon ...')
        if self.fileinfo['arch'] == 'ARM':
            print_not_supported('Architecture ARM not yet supported; currently under development')
        if self.fileinfo['format'] == '?':
            print_not_supported('File format not recognized: ' + ftype)
        self.initialized = True

    def save(self):
        xinfoname = self.get_xinfo_filename()
        xinfo = {}
        xinfo['timeline'] = self.timeline
        xinfo['file'] = self.fileinfo
        try:
            with open(xinfoname,'w') as fp:
                json.dump(xinfo,fp,indent=3)
        except Exception as e:
            exit_with_msg('Error in saving xinfo file: ' + str(e))

    def __str__(self):
        lines = []
        if self.initialized:
            lines.append('name    ' + self.fileinfo['name'])
            lines.append('size    ' + str(self.fileinfo['size']))
            lines.append('md5     ' + self.fileinfo['md5'])
            lines.append('arch    ' + self.fileinfo['arch'])
            lines.append('format  ' + self.fileinfo['format'])
        else:
            lines.append('No file information found')
        return '\n'.join(lines)

def get_xinfo(path,filename):
    xinfo = XInfo(path,filename)
    xinfoname = xinfo.get_xinfo_filename()
    if os.path.isfile(xinfoname):
        xinfo.load()
    else:
        xinfo.discover()
        xinfo.save()
    return xinfo
    
def get_path(xname,checkresults=False):
    try:
        name = os.path.abspath(xname)
        path = os.path.dirname(name)
        filename = os.path.basename(name)
        if os.path.isfile(filename):
            if checkresults:
                UF.check_analysis_results(path,filename)
        else:
            raise UF.CHBFileNotFoundError(filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)
    return (path,filename)

def extract(path,filename,args,xinfo):
    deps = args.thirdpartysummaries

    if not (xinfo.is_mips() or xinfo.is_arm() or xinfo.is_x86()):
        print_architecture_failure(xinfo)
    if not (xinfo.is_elf() or xinfo.is_pe32()):
        print_format_failure(xinfo)

    hints = {}
    if args.hints:
        try:
            with open(args.hints) as fp:
                hints = json.load(fp)
        except Exception as e:
            exit_with_msg('Error in loading fixup file: ' + str(e))
    try:
        if not UF.check_executable(path,filename):
            am = AM.AnalysisManager(path,filename,deps=deps,
                                    mips=xinfo.is_mips(),
                                    arm=xinfo.is_arm(),
                                    elf=xinfo.is_elf(),
                                    hints=hints)
            print('Extracting executable content into xml ...')
            result = am.extract_executable('-extract')
            if not (result == 0):
                exit_with_msg('Error in extracting executable; please check format')
            am.save_extract()
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        exit(1)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

def dll_results_tostring(args,result):
    lines = []
    summaryproblems = {}
    nosummaries = {}
    for dll in sorted(result):
        lines.append('')
        lines.append(dll)
        for fname in sorted(result[dll]):
            lines.append('')
            lines.append('  ' + fname)
            for instr in sorted(result[dll][fname],key=lambda i:(i.asmfunction.faddr,i.iaddr)):
                faddr = instr.asmfunction.faddr
                try:
                    lines.append('    ' + faddr + ',' + instr.iaddr + '  '
                                 + ','.join([ n + ':' + str(x)
                                              for (n,x) in instr.get_annotated_call_arguments()]))
                except UF.CHBSummaryNotFoundError:
                    nosummaries.setdefault(dll,{})
                    nosummaries[dll].setdefault(fname,0)
                    nosummaries[dll][fname] += 1
                except UF.CHBError as e:
                    summaryproblems.setdefault(dll,{})
                    summaryproblems[dll].setdefault(fname,[])
                    summaryproblems[dll][fname].append(faddr + ',' + instr.iaddr
                                                       + ': ' + str(e))
    if args.aggregate:
        lines.append(dll_aggregates_tostring(result))

    if len(summaryproblems) > 0:
        lines.append('')
        lines.append('Problems encountered with function summaries:')
        for dll in summaryproblems:
            for fname in summaryproblems[dll]:
                lines.append('')
                lines.append(dll + ',' + fname)
                for err in summaryproblems[dll][fname]:
                    print('  ' + str(err))

    if len(nosummaries) > 0:
        lines.append('\nMissing summaries:')
        for dll in sorted(nosummaries):
            lines.append('\n' + dll)
            for fname in sorted(nosummaries[dll]):
                lines.append(str(nosummaries[dll][fname]).rjust(5) + '  ' + fname)
                
    return '\n'.join(lines)

def dll_aggregates_tostring(result):
    lines = []
    aggregates = {} # dll -> function -> name of argument -> value -> count
    for dll in result:
        aggregates[dll] = {}
        for fname in result[dll]:
            fentry = aggregates[dll][fname] = {}
            for instr in result[dll][fname]:
                try:
                    arguments = instr.get_annotated_call_arguments()
                    for (name,v) in arguments:
                        pv = str(v)
                        fentry.setdefault(name,{})
                        fentry[name].setdefault(pv,0)
                        fentry[name][pv] += 1
                except UF.CHBError:
                    pass
    for dll in sorted(aggregates):
        lines.append('')
        lines.append(dll)
        for fname in sorted(aggregates[dll]):
            lines.append('')
            lines.append(fname)
            for argname in sorted(aggregates[dll][fname]):
                lines.append('')
                lines.append('    ' + argname)
                argentry = aggregates[dll][fname][argname]
                for pv in sorted(argentry):
                    lines.append('      ' + str(argentry[pv]).rjust(2) + '  ' + pv)
    return '\n'.join(lines)

def ioc_results_tostring(args,iocresults,problems):
    lines = []
    for ioc in sorted(iocresults):
        lines.append(('-' * 80) + '\n' + str(ioc) + '\n' + ('-' * 80))
        for rn in sorted(iocresults[ioc]):
            lines.append(rn)
            results = {}
            for (faddr,iaddr,arg) in iocresults[ioc][rn]:
                if args.constants:
                    if not arg.is_const(): continue
                argval = str(arg)
                results.setdefault(argval,[])
                results[argval].append((faddr,iaddr))
            for argval in sorted(results):
                lines.append(str(len(results[argval])).rjust(8) + '  ' + str(argval))
                if args.verbose:
                    for (faddr,iaddr) in sorted(results[argval]):
                        lines.append((' ' * 12) + faddr + ':' + iaddr)

    if len(problems) > 0:
        lines.append('\nProblems encountered:')
        lines.append('-' * 80)
        for p in problems:
            lines.append(p)
            for dll in problems[p]:
                lines.append('  ' + dll)
                for fname in problems[p][dll]:
                    lines.append('    ' + fname)
                    for (faddr,iaddr,_,_) in problems[p][dll][fname]:
                        lines.append('      ' + faddr + ',' + iaddr)

    return '\n'.join(lines)

def unresolved_calls_tostring(args,unrcalls):
    lines = []
    globaltargets = {}
    othertargets = {}
    for f in unrcalls:
        lines.append(f)
        for i in unrcalls[f]:
            lines.append('   ' + str(i))
            tgt = str(i.get_unresolved_call_target())
            if i.has_global_value_unresolved_call_target():
                globaltargets.setdefault(tgt,[])
                globaltargets[tgt].append(str(f) + ': ' + str(i.iaddr) + '  ' + str(i))
            else:
                othertargets.setdefault(tgt,[])
                othertargets[tgt].append(str(f) + ': ' + str(i.iaddr) + '  ' + str(i))

    lines.append('\nGlobal targets')
    for tgt in sorted(globaltargets):
        lines.append('\n' + tgt)
        for i in sorted(globaltargets[tgt]):
            lines.append('  ' + i)

    lines.append('\nOther targets')
    for tgt in sorted(othertargets):
        lines.append(tgt)

    return '\n'.join(lines)
