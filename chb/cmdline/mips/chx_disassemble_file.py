#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"Disassembles the file and displays some disassembly statistics."""
import argparse
import os
import shutil
import subprocess

import chb.cmdline.AnalysisManager as AM
import chb.util.fileutil as UF
import chb.util.xmlutil as UX

def parse():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='file to disassemble')
    parser.add_argument('--reset',action='store_true',
                            help='remove existing analysis results')
    parser.add_argument('--verbose','-v',help='output progress info',action='store_true')
    parser.add_argument('--specializations','-s',nargs='*',default=[],
                            help='function specializations present in system_info')
    parser.add_argument('--sh_init_size',help='provide size of .init section header')
    parser.add_argument('--preamble_cutoff',type=int,
                        help='minimum cutoff for function entry preamble',
                        default=12)
    args = parser.parse_args()
    return args

def extract(am,path,filename,deps,xuserdata=None):
    print('Extracting executable content into xml ...')
    try:
        chcmd = '-extract'
        result = am.extract_executable(chcmd=chcmd,xuserdata=xuserdata)
        if not (result == 0):
            print('*' * 80)
            print('Error in extracting executable; please check format')
            print('*' * 80)
            exit(1)
        am.save_extract()
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        exit(1)


if __name__ == '__main__':

    args = parse()

    xuserdata = []
    if args.sh_init_size:
        xdata = [ ('.init',[('size',args.sh_init_size)]) ]
        xuserdata = UX.create_xml_section_header_userdata(xdata)

    try:
        (path,filename,deps) = UF.get_path_filename_deps('mips-elf',args.filename)
        UF.check_analyzer()
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    am = AM.AnalysisManager(path,filename,deps=deps,mips=True,elf=True,
                            specializations=args.specializations)

    try:
        if not UF.check_executable(path,filename):
            extract(am,path,filename,deps,xuserdata=xuserdata)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if args.reset:
        chdir = UF.get_ch_dir(path,filename)
        if os.path.isdir(chdir):
            print('Removing ' + chdir)
            shutil.rmtree(chdir)
        if not UF.unpack_tar_file(path,filename):
            print('*' * 80)
            print('Error in unpacking tar.gz file with executable content')
            print('*' * 80)
            exit(1)

    try:
        am.disassemble(verbose=args.verbose,preamble_cutoff=args.preamble_cutoff)
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)

