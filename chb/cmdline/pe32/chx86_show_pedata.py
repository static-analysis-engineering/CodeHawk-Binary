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
"""Prints PE header and information on import table and raw sections."""

import argparse
import os
import shutil
import subprocess

import chb.util.fileutil as UF
import chb.util.xmlutil as UX

import chb.app.AppAccess as AP
import chb.cmdline.AnalysisManager as AM

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable')
    parser.add_argument('--headeronly',help='show only the PE header',action='store_true')
    parser.add_argument('--imports',help='show only import tables',action='store_true')
    parser.add_argument('--headers',help='show only section headers',action='store_true')
    parser.add_argument('--sections',help='show only sections',action='store_true')
    parser.add_argument('--section',help='show only section at given virtual address',
                        default=None)
    parser.add_argument('--extracthex',action='store_true',
                            help='take input from executable in hex form')
    parser.add_argument('--html',help='write output to html file',action='store_true')
    
    args = parser.parse_args()
    return args

def extract(path,filename,deps,extracthex):
    try:
        am = AM.AnalysisManager(path,filename,deps)
        chcmd = '-extracthex' if extracthex else '-extract'
        result = am.extract_executable(chcmd=chcmd)
        if not (result == 0):
            print('*' * 80)
            print('Error in extracting executable; please check format')
            print('*' * 80)
            exit(1)
        am.save_extract()
    except subprocess.CalledProcessError, args:
        print(args.output)
        print(args)
        exit(1)


if __name__ == '__main__':

    args = parse()

    try:
        (path,filename,deps) = UF.get_path_filename_deps('x86-pe',args.filename)
        if not UF.check_executable(path,filename):
            extract(path,filename,deps,args.extracthex)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    app = AP.AppAccess(path,filename)
    peheader = app.get_pe_header()                    # PEHeader object

    if args.headeronly: 
        print(peheader)
        exit(0)

    if args.imports:
        for i in peheader.get_import_tables(): print(str(i))
        exit(0)

    if args.headers:
        for h in peheader.get_section_headers(): print(str(h))
        exit(0)

    if args.sections:
        for s in peheader.get_sections(): print(str(s))
        exit(0)

    if not args.section is None:
        s = peheader.getsection(args.section)
        if s is None:
            print('Could not find section at virtual address ' + args.section)
        else:
            print(s)
        exit(0)

    print(peheader)
    for i in peheader.get_import_tables(): print(str(i))
    for h in peheader.get_section_headers(): print(str(h))

    if args.html:
        penodes = peheader.get_html()
        body = UX.get_html_body(penodes)
        with open('peheader.html','w') as fp:
            fp.write(UX.html_to_pretty(body,'pe-header'))

            
