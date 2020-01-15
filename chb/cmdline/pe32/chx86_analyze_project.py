# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma, Andrew McGraw
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
"""Invokes the Binary Analyzer on a set of executables, potentially in parallel.

Each executable is analyzed iteratively in a number of rounds until the analysis
stabilizes, or until a maximum number of rounds is reached (default: 12).
"""

import argparse
import json
import os
import subprocess
import shutil
import multiprocessing

import chb.util.fileutil as UF

import chb.cmdline.AnalysisManager as AM
import chb.app.AppAccess as AP


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('atfi',help='index in analysistargettable for x86-pe')
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
    parser.add_argument('--annotate',help='annotate pe sections',action='store_true')
    parser.add_argument('--maxprocesses',type=int,default=1,help='processes to run in parllel')
    args = parser.parse_args()
    return args

def extract(path,filename,deps,extracthex,annotate):
    print('Extracting executable content into xml ...')
    try:
        am = AM.AnalysisManager(path,filename,deps)
        chcmd = '-extracthex' if extracthex else '-extract'
        result = am.extract_executable(chcmd=chcmd)
        if not (result == 0):
            print('*' * 80)
            print('Error in extracting executable; please check format')
            print('*' * 80)
            return False
        else:
            am.save_extract()
            return True
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        False

def call_extraction(file_info, extracthex, reset, annotate):
    try:
        (path,filename,deps) = file_info
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if not UF.check_executable(path,filename):
        try:
            extract(path,filename,deps,extracthex, annotate)
        except subprocess.CalledProcessError as args:
            print(args.output)
            print(args)
            return

    if reset:
        chdir = UF.get_ch_dir(path,filename)
        if os.path.isdir(chdir):
            print('Removing ' + chdir)
            shutil.rmtree(chdir)
        if not UF.unpack_tar_file(path,filename):
            print('*' * 80)
            print('Error in unpacking tar.gz file with executable content')
            print('*' * 80)
            exit(1)

def extract_parallel(executables, args):
    count = 0
    for executable in sorted(executables):
        count += 1
        try:
            file_info = UF.get_path_filename_deps('x86-pe',executable)
        except UF.CHBDirectoryNotFoundError as e:
            print(e)
            continue

        while(len(multiprocessing.active_children()) >= args.maxprocesses):
            pass

        print("Extracting executable " + str(count) + " of " + str(len(executables)) + " ... ")
        multiprocessing.Process(target=call_extraction,
                                    args=(file_info,
                                              args.extracthex,
                                              args.reset,
                                              args.annotate)).start()

    while(len(multiprocessing.active_children()) > 0):
        pass

def analyze_parallel(executables, args):
    count = 0
    for executable in sorted(executables):
        count += 1
        try:
            file_info = UF.get_path_filename_deps('x86-pe',executable)
        except UF.CHBDirectoryNotFoundError as e:
            print(e)
            continue
        (path, filename, deps) = file_info

        while(len(multiprocessing.active_children()) >= args.maxprocesses):
            pass


        if (os.path.isfile(UF.get_executable_targz_filename(path, filename))):
                # and os.path.isdir(UF.get_statistics_dir(path, filename)))
            print("Analyzing executable " + str(count) + " of " + str(len(executables)) + " ... ")
            multiprocessing.Process(target=call_analysis,
                                        args=(file_info, args.iterations, args.asm)).start()
        else:
            print('Not analyzing: ' + filename)

    while(len(multiprocessing.active_children()) > 0):
        pass

def call_analysis(file_info, iterations, save_asm):
    (path, filename, deps) = file_info
    am = AM.AnalysisManager(path, filename, deps=deps)

    try:
        am.analyze(iterations=iterations,save_asm=save_asm)
    except subprocess.CalledProcessError as args:
        print(args.output)
        print(args)

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


if __name__ == '__main__':

    args = parse()

    UF.check_analyzer()

    executables = UF.get_atfi_executables('x86-pe',args.atfi)

    executable_names = [ UF.mk_atsc(args.atfi,atxi) for atxi in list(executables.keys()) ]

    extract_parallel(executable_names, args)
    analyze_parallel(executable_names, args)
