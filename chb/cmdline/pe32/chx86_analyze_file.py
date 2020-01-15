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
"""Invoke CodeHawk Binary Analyzer to analyze executable.

This script allows the user to perform data flow analysis on an ELF
executable.

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

To view the analysis results, run any of the following scripts on the same
executable: chx86_report_appcalls.py, chx86_report_socalls.py,
chx86_report_stringargs.py, chx86_show_call_targets.py, chx86_show_functions.py,
chx86_show_resultmetrics.py

If analysis results are present and they indicate that analysis has already
stabilized, no more analysis is performed. To start fresh, use the --reset
commandline option to delete any previous analysis results.
"""

import argparse
import json
import os
import subprocess
import shutil

import chb.util.fileutil as UF

import chb.cmdline.AnalysisManager as AM
import chb.app.AppAccess as AP

def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename',help='name of executable to be analyzed')
    parser.add_argument('--asm','-a',action='store_true',
                            help='save assembly code')
    parser.add_argument('--reset',action='store_true',
                            help='remove existing analysis results')
    parser.add_argument('--iterations',help='maximum number of iterations',
                            default=12,type=int)
    parser.add_argument('--extracthex',action='store_true',
                            help='take input from executable in hex form')
    parser.add_argument('--save_cfgs',action='store_true',
                            help='save control flow graphs')
    parser.add_argument('--verbose','-v',help='show intermediate results',
                            action='store_true')
    args = parser.parse_args()
    return args

def extract(path,filename,deps,extracthex):
    print('Extracting executable content into xml ...')
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
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        exit(1)


if __name__ == '__main__':

    args = parse()

    try:
        (path,filename,deps) = UF.get_path_filename_deps('x86-pe',args.filename)
        if not UF.check_executable(path,filename):
            extract(path,filename,deps)            
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    UF.check_analyzer()
    am = AM.AnalysisManager(path,filename,deps=deps)

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
        am.analyze(iterations=args.iterations,save_asm=args.asm,verbose=args.verbose)
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        exit (1)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    md5profilename = UF.get_md5profile_filename(path,filename)
    try:
        app = AP.AppAccess(path,filename)
        md5profile = app.get_md5_profile()
        summary = app.get_result_metrics_summary()
    except IOError as e:
        print(e)
    else:
        print('Saving md5 profile and results summary')
        with open(md5profilename,'w') as fp:
            json.dump(md5profile,fp,sort_keys=True,indent=4)
        UF.save_results_summary(path,filename,summary)
