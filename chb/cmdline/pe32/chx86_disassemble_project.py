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
"""Script to disassemble a set of executables in parallel."""

import argparse
import os
import shutil
import subprocess
import multiprocessing

import chb.util.fileutil as UF
import chb.cmdline.AnalysisManager as AM


def parse(): 
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('atfi',help='index in analysistargettable for x86-pe')
    parser.add_argument('--xml',help='save disassembly status info in xml',
                            action='store_true')
    parser.add_argument('--reset',action='store_true',
                            help='remove existing analysis results')
    parser.add_argument('--reduce',action='store_true',
                            help='remove ch directory after disassembly (saves space)')
    parser.add_argument('--extracthex',action='store_true',
                            help='take input from executable in hex form')
    parser.add_argument('--maxprocesses',help='maximum number of files to analyze in parallel',
                            default=1,type=int)
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
            return False
        else:
            am.save_extract()
            return True
    except subprocess.CalledProcessError as args:
        print(args.output)
        print(args)
        return False

    
def call_disassembly(file_info, xml, reducech):
    (path, filename, deps) = file_info
    am = AM.AnalysisManager(path, filename, deps=deps)

    try:
        am.disassemble(save_xml=xml)
        if reducech:
            chdir = UF.get_ch_dir(path, filename)
            if os.path.isdir(chdir):
                print('Removing ' + chdir)
                shutil.rmtree(chdir)
    except subprocess.CalledProcessError as args:
        print(args.output)
        print(args)

#Threading? Memory Management?
def disassemble_parallel(executables, args):
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

        if os.path.isfile(UF.get_executable_targz_filename(path, filename)):
            print('Disassembling executable ' + filename
                      + ' (' + str(count) + ' of ' + str(len(executables))
                      + ') ... ') 
            multiprocessing.Process(target=call_disassembly,
                                        args=(file_info, args.xml, args.reduce)).start()

    while(len(multiprocessing.active_children()) > 0):
        pass

def call_extraction(file_info, extracthex, reset):
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
                                    args=(file_info, args.extracthex, args.reset)).start()

    while(len(multiprocessing.active_children()) > 0):
        pass

if __name__ == '__main__':

    args = parse()

    UF.check_analyzer()

    executables = UF.get_atfi_executables('x86-pe',args.atfi)

    executable_names = [ UF.mk_atsc(args.atfi,atxi) for atxi in list(executables.keys()) ]

    extract_parallel(executable_names, args)
    disassemble_parallel(executable_names, args)
