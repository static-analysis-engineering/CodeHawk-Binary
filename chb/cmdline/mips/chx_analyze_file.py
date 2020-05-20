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
"""Invoke CodeHawk Binary Analyzer to analyze MIPS executable.

This script allows the user to perform data flow analysis on a MIPS
executable in ELF format.

The script takes the filename of the executable or a pre-registered
nickname for the executable.

The script invokes the CodeHawk Binary Analyzer iteratively until the
analysis stabilizes, or the maximum number of iterations is reached
(default: 12). It prints out intermediate summary results for each
iteration.

The analysis results are saved in the directories 
   <executable-name>.ch/analysis
   <executable-name>.ch/results
in the same directory as the executable.

To view the summary analysis results, run the following scripts on the same
executable: chx_show_resultmetrics.py.

If analysis results are present and they indicate that analysis has already
stabilized, no more analysis is performed. To start fresh, use the --reset
commandline option to delete any previous analysis results.
"""

import argparse
import os
import subprocess
import shutil

import chb.util.fileutil as UF
import chb.cmdline.AnalysisManager as AM


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable to be analyzed')
    parser.add_argument('--reset',action='store_true',
                            help='remove existing analysis results')
    parser.add_argument('--iterations','-i',help='maximum number of iterations',
                            default=12,type=int)
    parser.add_argument('--verbose','-v',help='output intermediate resutls',
                            action='store_true')
    parser.add_argument('--specializations','-s',nargs='*',default=[],
                            help='function specializations present in system_info')
    args = parser.parse_args()
    return args

def extract(path,filename,deps):
    print('Extracting executable content into xml ...')
    try:
        am = AM.AnalysisManager(path,filename,deps,elf=True,mips=True)
        chcmd = '-extract'
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
        print(str(e.wrap()))
        exit(1)

    UF.check_analyzer()
    am = AM.AnalysisManager(path,filename,deps=deps,mips=True,elf=True,
                                specializations=args.specializations)

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
        am.analyze(iterations=args.iterations,verbose=args.verbose)
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        exit (1)

