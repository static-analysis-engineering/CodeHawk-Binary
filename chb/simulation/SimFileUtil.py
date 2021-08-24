# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021      Aarno Labs
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
"""Utilities to support file operations performed by simulation.

Simulated files are assumed to be located in the 'simulation disk', a subdirectory
of the directory from which the simulation is run, with the name 'simdisk'.

The simdisk is assumed to have the same structure as the originating filesystem.
Files with absolute path names are made relative to simdisk. For example, a
reference to a file /var/tmp/dconf is created in the directory simdisk/var/tmp .
Relative names are resolved relative to the current working directory (if known).

File operations are only performed if the boolean file_operations_enabled is set.
"""

import os

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV


def sim_mkdir(pathname: str) -> int:
    if pathname.startswith("/"):
        simpathname = os.path.join("simdisk", pathname[1:])
        if os.path.exists(simpathname):
            pass
        else:
            os.makedirs(simpathname)
        return 0
    return -1


def sim_openfile(filename: str, mode: str) -> SSV.SimSymbolicFilePointer:
    print("Open file " + filename)
    if filename.startswith("/"):
        simfilename = os.path.join("simdisk", filename[1:])
        simpathname = os.path.dirname(simfilename)
        if not os.path.exists(simpathname):
            print("make dir: " + simpathname + " (" + simfilename + ")")
            os.makedirs(simpathname)
        print("Open " + simfilename + " with mode " + mode)
        fp = open(simfilename, mode)
        return SSV.mk_filepointer(simfilename, fp)
    else:
        return SSV.mk_filepointer(simfilename, filename, defined=False)


def sim_file_exists(filename: str) -> bool:
    if filename.startswith("/"):
        simfilename = os.path.join("simdisk", filename[1:])
        return os.path.isfile(simfilename)
    else:
        return False
