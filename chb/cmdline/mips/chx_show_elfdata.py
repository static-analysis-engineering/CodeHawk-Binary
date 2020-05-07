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

import argparse
import subprocess

import chb.util.fileutil as UF
import chb.app.AppAccess as AP
import chb.cmdline.AnalysisManager as AM

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename',help='name of executable')
    args = parser.parse_args()
    return args

def extract(path,filename,deps):
    print('Extracting executable content into xml ...')
    try:
        am = AM.AnalysisManager(path,filename,deps)
        chcmd = '-extract_elf'
        result = am.extract_executable(chcmd=chcmd)
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

    try:
        (path,filename,deps) = UF.get_path_filename_deps('mips-elf',args.filename)
        if not UF.check_executable(path,filename):
            extract(path,filename,deps)
    except UF.CHBError as e:
        print(e.wrap())
        exit(1)

    app = AP.AppAccess(path,filename,initialize=False,mips=True)
    elfheader = app.get_elf_header()                    # ELFHeader object

    try:
        print(elfheader)
    except UF.CHBError as e:
        print(e.wrap())
        exit(1)
