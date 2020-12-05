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
"""Extracts executable content and saves it in xml."""

import argparse
import json
import os
import shutil
import subprocess

import chb.cmdline.AnalysisManager as AM
import chb.util.fileutil as UF
import chb.util.xmlutil as UX


def parse():
    
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='file to extract')
    parser.add_argument('--reset',action='store_true',
                        help='remove existing xml extract and analysis directories')
    parser.add_argument('--fixup',help='name of json file with disassembly fixup')
    parser.add_argument('--force_fixup',help='replace existing user data file',
                        action='store_true')
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
        print(e.args.output)
        print(e.args)
        exit(1)


if __name__ == '__main__':

    args = parse()

    fixup = {}
    if args.fixup:
        try:
            with open(args.fixup) as fp:
                fixup = json.load(fp)['fixups']
        except Exception as e:
            print('*' * 80)
            print('Error in loading fixup file: ' + str(e))
            print('*' * 80)
            exit(1)

    try:
        (path,filename,deps) = UF.get_path_filename_deps('mips-elf',args.filename)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    UF.check_analyzer()

    if args.reset:
        chdir = UF.get_ch_dir(path,filename)
        if os.path.isdir(chdir):
            print('Removing ' + chdir)
            shutil.rmtree(chdir)
        xmlextract = UF.get_executable_targz_filename(path,filename)
        if os.path.isfile(xmlextract):
            print('Removing ' + xmlextract)
            os.remove(xmlextract)

    am = AM.AnalysisManager(path,filename,deps=deps,mips=True,elf=True,
                            fixup=fixup,force_fixup=args.force_fixup)

    if not UF.check_executable(path,filename):
        extract(am,path,filename,deps)

    if not UF.unpack_tar_file(path,filename):
        print('*' * 80)
        print('Error in unpacking tar.gz file with executable content')
        print('*' * 80)
        exit(1)

    try:
        am.disassemble()
    except subprocess.CalledProcessError as e:
        print(e.args.output)
        print(e.args)

